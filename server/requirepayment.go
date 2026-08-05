package server

import (
	"context"
	"fmt"
)

// requirePayment — the gate. Ported from requirePayment.ts.
//
// Security posture (fail closed): the only way RequirePayment authorizes a
// caller to proceed is by returning (nil, nil), which happens solely after the
// authorization server confirms an on-demand charge settled. Every other
// outcome — payment still required, or any infrastructure error — returns a
// non-nil Challenge or a non-nil error, both of which the caller must treat as
// "do not run the metered operation".

// PaymentRequest describes one metered call to gate.
type PaymentRequest struct {
	// Price is what to charge for this call. The amount actually charged is
	// max(Price, the merchant's MinimumPayment).
	Price Amount

	// User is the caller's account id — the `sub` from a passing CheckToken.
	// Required; without an authenticated caller there is nobody to charge.
	User string

	// SourceAccountToken is the caller's connection/OAuth token for on-demand
	// (pull-mode) charging. Wallet-grade secret. Optional: without it, the
	// caller is sent a challenge to pay out-of-band.
	SourceAccountToken string

	// PaymentRequestID ties this charge to an existing payment lifecycle
	// (idempotency). Optional.
	PaymentRequestID string

	// Session, when set, charges locally against the request-scoped payment
	// session (opened from a detected retry credential via
	// Merchant.OpenPaymentSession) instead of issuing a network /charge call.
	// Multiple RequirePayment calls sharing a Session settle once, for the
	// sum actually charged, when the caller closes it via
	// Merchant.CloseSession. Optional — nil preserves the on-demand /charge
	// behavior.
	Session *PaymentSession

	// Resource is the resource URL recorded in the challenge for activity labels.
	// Optional.
	Resource string

	// ExistingPaymentID, when set, is consulted before creating a new payment
	// request so a re-challenge reuses an in-flight payment. Optional.
	ExistingPaymentID func(ctx context.Context) (string, error)
}

// RequirePayment gates a metered operation. It returns:
//
//   - (nil, nil)            the charge settled; the caller may proceed.
//   - (*Challenge, nil)     payment is required; emit the Challenge as an
//     MCP/JSON-RPC error (or HTTP 402) and do not proceed.
//   - (nil, error)          an infrastructure error; do not proceed.
func (m *Merchant) RequirePayment(ctx context.Context, pr PaymentRequest) (*Challenge, error) {
	if pr.User == "" {
		return nil, fmt.Errorf("atxp server: RequirePayment needs a User (authenticate the caller first)")
	}
	if !pr.Price.IsPositive() && !m.minimum.IsPositive() {
		return nil, fmt.Errorf("atxp server: RequirePayment needs a positive Price or MinimumPayment")
	}

	// Charge at least the configured floor. (The TS reference charges the bare
	// price on the pull path and only applies the floor to the challenge; we
	// apply the floor everywhere so MinimumPayment is actually enforced — under-
	// charging is a money bug.)
	paymentAmount := Max(m.minimum, pr.Price)

	destID, err := m.destinationAccountID(ctx)
	if err != nil {
		return nil, err
	}
	destNetwork, err := extractNetworkFromAccountID(destID)
	if err != nil {
		return nil, err
	}
	destAddress, err := extractAddressFromAccountID(destID)
	if err != nil {
		return nil, err
	}

	charge := ChargeRequest{
		Options: []chargeOptionWire{{
			Network:  destNetwork,
			Currency: m.currency,
			Address:  destAddress,
			Amount:   paymentAmount.String(),
		}},
		SourceAccountID:      pr.User,
		DestinationAccountID: destID,
		PayeeName:            m.payeeName,
		SourceAccountToken:   pr.SourceAccountToken,
		PaymentRequestID:     pr.PaymentRequestID,
	}

	// Prefer a request-scoped session: charge locally and let the caller
	// settle once (for the sum actually charged) when it closes the session.
	// Without one, fall back to the on-demand network /charge — preserving
	// the original per-call behavior for callers that don't use sessions.
	if pr.Session != nil {
		if pr.Session.Charge(paymentAmount) {
			m.logger.Infof("charged %s to session for source %s", paymentAmount.String(), pr.User)
			return nil, nil
		}
	} else {
		charged, err := m.paymentServer.Charge(ctx, charge)
		if err != nil {
			return nil, err // fail closed: an errored charge is not a paid charge
		}
		if charged {
			m.logger.Infof("charged %s for source %s", paymentAmount.String(), pr.User)
			return nil, nil
		}
	}

	// Idempotency: reuse an in-flight payment if the caller knows of one.
	if pr.ExistingPaymentID != nil {
		existingID, err := pr.ExistingPaymentID(ctx)
		if err != nil {
			return nil, fmt.Errorf("atxp server: look up existing payment id: %w", err)
		}
		if existingID != "" {
			sources := m.fetchAllSources(ctx, destNetwork, destAddress)
			return m.buildOmniError(ctx, existingID, paymentAmount, sources, pr)
		}
	}

	sources := m.fetchAllSources(ctx, destNetwork, destAddress)
	options := make([]chargeOptionWire, 0, len(sources))
	for _, s := range sources {
		options = append(options, chargeOptionWire{
			Network:  s.Chain,
			Currency: m.currency,
			Address:  s.Address,
			Amount:   paymentAmount.String(),
		})
	}
	paymentRequest := ChargeRequest{
		Options:              options,
		SourceAccountID:      pr.User,
		DestinationAccountID: destID,
		PayeeName:            m.payeeName,
	}
	paymentID, err := m.paymentServer.CreatePaymentRequest(ctx, paymentRequest)
	if err != nil {
		return nil, err
	}
	m.logger.Infof("created payment request %s", paymentID)
	return m.buildOmniError(ctx, paymentID, paymentAmount, sources, pr)
}

// fetchAllSources combines the primary ATXP destination address with any
// chain-specific addresses from the destination. Best-effort: a Sources error
// degrades to the ATXP-only option rather than failing the challenge. Ported
// from requirePayment.ts fetchAllSources.
func (m *Merchant) fetchAllSources(ctx context.Context, destNetwork, destAddress string) []Source {
	sources := []Source{{Chain: destNetwork, Address: destAddress}}
	fetched, err := m.destination.Sources(ctx, []string{"tempo"})
	if err != nil {
		m.logger.Warnf("failed to fetch destination sources, using ATXP option only: %v", err)
		return sources
	}
	return append(sources, fetched...)
}

// buildOmniError assembles the omni-challenge and injects the signed opaque
// identity into each MPP challenge. Ported from requirePayment.ts buildOmniError.
func (m *Merchant) buildOmniError(ctx context.Context, paymentID string, amount Amount, sources []Source, pr PaymentRequest) (*Challenge, error) {
	// Fetch (TTL-cached) the protocol "supported" params so the challenge can
	// advertise the metered variants: x402 upto (facilitator address) and MPP
	// session (Tempo/Solana channel settler). On failure each returns
	// empty/nil and only the base variant (x402 exact / MPP charge) is
	// advertised.
	facilitatorAddresses := fetchUptoFacilitatorAddresses(ctx, m.authServer, m.httpc, m.logger)
	mppSupported := fetchMppSupported(ctx, m.authServer, m.httpc, m.logger)

	payment := buildPaymentOptions(buildPaymentOptionsArgs{
		Amount:               amount,
		Sources:              sources,
		Resource:             pr.Resource,
		ChallengeID:          paymentID,
		Now:                  m.now(),
		FacilitatorAddresses: facilitatorAddresses,
		MppSession:           mppSupported.Tempo,
		MppSolanaSession:     mppSupported.Solana,
	})

	if len(payment.x402.Accepts) == 0 && len(sources) > 0 {
		m.logger.Warnf("no x402-compatible networks among %d sources; x402 clients will see no options", len(sources))
	}

	// Inject signed identity into MPP challenges' opaque field so the caller can
	// be re-identified after Authorization: Payment displaces the bearer token.
	for i := range payment.mpp {
		id := m.opaque.sign(pr.User, payment.mpp[i].ID)
		payment.mpp[i].Opaque = map[string]any{"atxp_sub": id.Sub, "sig": id.Sig}
	}

	return omniChallengeMcpError(m.authServer, paymentID, &amount, payment.x402, payment.mpp)
}
