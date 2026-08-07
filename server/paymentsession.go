package server

import (
	"context"
	"fmt"
	"strconv"
	"sync"
)

// UnderpaymentError is returned by CloseSession when a settle call succeeded
// but for less than the amount actually charged locally (Spent). Real money
// moved, so there is nothing to retry, but the caller must not treat this as
// a completed payment: do not serve the resource or credit anything for it.
//
// This is deliberately not a network/infrastructure failure: it means the
// settle response itself came back clean, just short. See CloseSession's
// doc comment for why this check exists (the x402 "exact" scheme in
// particular can settle for less than a credential claims elsewhere in the
// same payload).
//
// Confirmed live against production (2026-08-07, Base mainnet): for x402
// "exact", auth.atxp.ai's own /settle/x402 already rejects a credential
// whose accepted.amount doesn't match its actual signed authorization.value
// (HTTP 400, nothing settles), so this error path did not fire for that
// specific attack shape; the AS closed it one layer down. This check is
// still real defense-in-depth (a merchant-side pricing bug, or any future
// change in the AS's behavior, would still need it), but for x402 exact its
// load-bearing-ness is unconfirmed rather than demonstrated. Whether the AS
// enforces the same consistency for the ATXP-native protocol or MPP is
// untested. ATXP-native's trust model differs (the AS computes the charge
// itself against its own ledger rather than verifying a third-party
// signature), so the same attack shape may not even apply there; MPP is
// simply unverified. Don't assume either has the same backend guarantee
// x402 exact was shown to have.
type UnderpaymentError struct {
	Spent   Amount
	Settled Amount
	// ParseError is set instead of a meaningful Settled when the settle
	// response's amount could not be parsed at all. Treated as a failure
	// too, since an amount that can't be verified isn't a verified amount.
	ParseError error
}

func (e *UnderpaymentError) Error() string {
	if e.ParseError != nil {
		return fmt.Sprintf("atxp server: settle response amount was unparseable (charged %s): %v", e.Spent.String(), e.ParseError)
	}
	return fmt.Sprintf("atxp server: settled amount %s is less than the %s actually charged", e.Settled.String(), e.Spent.String())
}

func (e *UnderpaymentError) Unwrap() error { return e.ParseError }

// PaymentSession accumulates local charges against one detected payment
// credential across multiple RequirePayment calls, so N calls within one
// request settle once (for the sum actually charged) instead of issuing N
// network round trips. Ported from paymentSession.ts PaymentSessionState.
//
// Unlike the TS reference (whose Express middleware opens/closes a session
// implicitly per request via AsyncLocalStorage), chit has no framework layer:
// the caller opens a session from a detected retry credential
// (Merchant.OpenPaymentSession), threads it into each PaymentRequest.Session,
// and closes it exactly once — typically via defer — when its request scope
// ends (Merchant.CloseSession).
type PaymentSession struct {
	mu sync.Mutex

	protocol      Protocol
	credential    string
	sctx          SettlementContext
	requiresClose bool // true for an MPP session (channel) credential — see settleSession

	cap          Amount
	capUnlimited bool // true when the cap could not be derived (no limit)
	spent        Amount
	settled      bool
	settling     bool // guards against re-entrant Close calls

	settleResult    SettleResult
	settleResultSet bool
}

// SettleResult returns the result of the settle call CloseSession made, and
// whether one has happened yet (false before Close, or if Close no-op'd on a
// zero-spend one-shot credential). Check this after CloseSession succeeds
// before trusting the session as paid for its full intended amount: for the
// x402 "exact" scheme in particular, chit cannot verify that a credential's
// self-reported accepted.amount matches what the payer actually signed in
// authorization.value. The facilitator only ever settles the real signed
// value; SettledAmount is the actual amount that moved on-chain. Compare it
// against your own expected price before crediting anything.
func (s *PaymentSession) SettleResult() (SettleResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settleResult, s.settleResultSet
}

// Charge records a charge of cost against the session. It returns false (and
// leaves the accumulated total unchanged) if this charge would exceed the
// credential's authorized cap — the caller should then fall through to
// building a new payment challenge, exactly as an on-demand charge decline
// would. Ported from PaymentSessionState.charge.
func (s *PaymentSession) Charge(cost Amount) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.spent.Add(cost)
	if !s.capUnlimited && next.GreaterThan(s.cap) {
		return false
	}
	s.spent = next
	return true
}

// Spent returns the sum of charges recorded so far.
func (s *PaymentSession) Spent() Amount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.spent
}

// Cap returns the session's authorized ceiling and whether it is unlimited
// (the credential's amount could not be derived).
func (s *PaymentSession) Cap() (cap Amount, unlimited bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cap, s.capUnlimited
}

// OpenPaymentSession opens a payment session for a detected retry credential.
// Deriving the cap is local (no network call) — it parses the credential (and,
// for x402, resolves the matching accept from sctx.PaymentRequirements) to
// find the authorized amount. Ported from atxpContext.ts openPaymentSession /
// paymentSession.ts buildPaymentSession.
func (m *Merchant) OpenPaymentSession(detected CredentialDetection, sctx SettlementContext) *PaymentSession {
	cap, unlimited := deriveSessionCap(detected.Protocol, detected.Credential, sctx, m.logger)
	return &PaymentSession{
		protocol:      detected.Protocol,
		credential:    detected.Credential,
		sctx:          sctx,
		requiresClose: detected.Protocol == ProtocolMPP && isMppSessionCredential(detected.Credential),
		cap:           cap,
		capUnlimited:  unlimited,
	}
}

// CloseSession settles a payment session at most once, for the amount
// actually charged (Spent), and is safe to call more than once (e.g. from a
// deferred call on every return path) — later calls are no-ops once settled.
//
// Two protocol-shape-dependent rules apply, mirroring settlePaymentSession:
//   - An MPP session (channel) credential settles even at Spent()==0, since
//     that close refunds the deposit locked at authorize. One-shot ATXP/x402
//     credentials have nothing to settle at zero spend and no-op instead.
//   - On settle failure, a channel credential is left unsettled so a later
//     call can re-drive the on-chain close (idempotent); one-shot credentials
//     are marked settled regardless (nothing to re-drive; reconcile from the
//     returned error).
func (m *Merchant) CloseSession(ctx context.Context, session *PaymentSession) error {
	if session == nil {
		return nil
	}

	session.mu.Lock()
	if session.settled || session.settling {
		session.mu.Unlock()
		return nil
	}
	if session.spent.IsZero() && !session.requiresClose {
		session.mu.Unlock()
		return nil
	}
	session.settling = true
	protocol, credential, sctx, spent := session.protocol, session.credential, session.sctx, session.spent
	session.mu.Unlock()

	settlement, err := m.Settlement(ctx)
	if err != nil {
		session.mu.Lock()
		session.settling = false
		session.mu.Unlock()
		return err
	}

	result, settleErr := settlement.Settle(ctx, protocol, credential, &sctx, &spent)

	session.mu.Lock()
	defer func() {
		session.settling = false
		session.mu.Unlock()
	}()
	if settleErr != nil {
		m.logger.Errorf("settle_failed_at_close protocol=%s amount=%s: %v", protocol, spent.String(), settleErr)
		if !session.requiresClose {
			session.settled = true
		}
		return settleErr
	}

	// The /settle call succeeding is not the same as settling for enough. For
	// the x402 "exact" scheme in particular, the facilitator settles for
	// exactly whatever authorization.value the payer actually signed, which a
	// credential can misreport relative to the accepted.amount it claims
	// elsewhere in the same payload. chit's local cap check (session.Charge)
	// only verifies against what THIS merchant advertised, never against the
	// credential's real signed value. Treat an underpayment as a settle
	// failure: real money moved, so there is nothing to retry, but the caller
	// must not serve or credit anything for it. Fail closed on an unparseable
	// amount too, since an amount we can't verify is not a verified amount.
	settled, parseErr := ParseAmount(result.SettledAmount)
	if parseErr != nil || spent.GreaterThan(settled) {
		session.settled = true
		session.settleResult = result
		session.settleResultSet = true
		underErr := &UnderpaymentError{Spent: spent, Settled: settled, ParseError: parseErr}
		m.logger.Errorf("settle_underpaid_at_close protocol=%s spent=%s settledAmount=%q: %v", protocol, spent.String(), result.SettledAmount, underErr)
		return underErr
	}

	session.settled = true
	session.settleResult = result
	session.settleResultSet = true
	tx := "<already-settled>"
	if result.TxHash != nil {
		tx = *result.TxHash
	}
	m.logger.Infof("settled %s at session close: txHash=%s amount=%s", protocol, tx, result.SettledAmount)
	return nil
}

// deriveSessionCap derives the authorized cap from a detected credential.
// Best-effort: when the amount cannot be parsed reliably for a protocol, it
// returns (zero, true) — unlimited — so the single-charge path still works.
// Ported from paymentSession.ts deriveCap.
func deriveSessionCap(protocol Protocol, credential string, sctx SettlementContext, logger Logger) (Amount, bool) {
	switch protocol {
	case ProtocolX402:
		payload := parseCredentialJSON(credential)
		if payload == nil {
			payload = map[string]any{}
		}
		if accept := selectX402Accept(payload, sctx.PaymentRequirements, nil); accept != nil {
			if cap, err := AmountFromMicroString(accept.Amount); err == nil {
				return cap, false
			}
		}

	case ProtocolMPP:
		parsed := parseCredentialJSON(credential)
		if challenge, ok := parsed["challenge"].(map[string]any); ok {
			amount, method := mppChallengeAmount(challenge)
			if amount != "" {
				switch method {
				case "solana":
					if cap, err := AmountFromMicroString(amount); err == nil {
						return cap, false
					}
				default:
					// Tempo (human-readable decimal) and any unrecognized
					// method: treat as decimal to avoid under-scaling the cap
					// (dividing a decimal by 1e6 would falsely re-challenge an
					// already-paid request).
					if cap, err := ParseAmount(amount); err == nil {
						return cap, false
					}
				}
			}
		}

	default: // ATXP
		parsed := parseCredentialJSON(credential)
		if options, ok := parsed["options"].([]any); ok {
			for _, o := range options {
				m, ok := o.(map[string]any)
				if !ok {
					continue
				}
				if amount := anyToAmountString(m["amount"]); amount != "" {
					if cap, err := ParseAmount(amount); err == nil {
						return cap, false
					}
				}
			}
		}
		if amount := anyToAmountString(parsed["amount"]); amount != "" {
			if cap, err := ParseAmount(amount); err == nil {
				return cap, false
			}
		}
	}

	if logger != nil {
		logger.Warnf("PaymentSession: could not derive cap for %s credential, defaulting to no limit", protocol)
	}
	return Amount{}, true
}

// mppChallengeAmount reads the amount + method from an MPP credential's
// challenge object: amount from challenge.request.amount, falling back to
// challenge.amount; method from challenge.method.
func mppChallengeAmount(challenge map[string]any) (amount, method string) {
	method, _ = challenge["method"].(string)
	if request, ok := challenge["request"].(map[string]any); ok {
		if a := anyToAmountString(request["amount"]); a != "" {
			return a, method
		}
	}
	return anyToAmountString(challenge["amount"]), method
}

// anyToAmountString stringifies a decoded-JSON amount value that may be
// either a string or a number (json.Unmarshal decodes numbers as float64 into
// map[string]any), matching the TS reference's `string | number` amount type.
func anyToAmountString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}
