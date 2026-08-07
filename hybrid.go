package atxp

import "context"

// HybridAccount composes OAuth identity from one Account with payment
// authorization from another. It exists for the case where the account
// capable of completing the OAuth handshake (typically an ATXPAccount) is
// not the account that should actually pay: a self-custodial signer (e.g.
// x402signer.X402SignerAccount) has no ATXP identity of its own and cannot
// complete an OAuth handshake (see x402signer's package doc), but a resource
// gated behind an OAuth 401 still requires one before it ever issues a
// payment challenge.
//
// Live-verified 2026-08-06: an ATXPAccount for Identity plus an
// x402signer.X402SignerAccount for Payments settles a real x402 payment
// against an OAuth-gated third-party merchant, confirmed on-chain.
//
// If the resource is gated purely by a bare 402 (no OAuth 401 first),
// Payments alone is sufficient and HybridAccount is unnecessary.
type HybridAccount struct {
	// Identity supplies AccountID, SignChallenge, and SpendPermission — the
	// OAuth-handshake half.
	Identity Account
	// Payments supplies Authorize — the actual payment-signing half.
	Payments Account
}

func (h *HybridAccount) AccountID(ctx context.Context) (string, error) {
	return h.Identity.AccountID(ctx)
}

func (h *HybridAccount) SignChallenge(ctx context.Context, codeChallenge string) (string, error) {
	return h.Identity.SignChallenge(ctx, codeChallenge)
}

func (h *HybridAccount) SpendPermission(ctx context.Context, resourceURL string) (string, error) {
	return h.Identity.SpendPermission(ctx, resourceURL)
}

func (h *HybridAccount) Authorize(ctx context.Context, p AuthorizeParams) (AuthorizeResult, error) {
	return h.Payments.Authorize(ctx, p)
}
