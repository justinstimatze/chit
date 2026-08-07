package server

import (
	"context"
	"strconv"
	"sync"
)

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
	session.settled = true
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
