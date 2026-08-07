package atxp

import (
	"context"
	"errors"
	"testing"
)

type stubAccount struct {
	id             string
	jwt            string
	spendToken     string
	authorizeErr   error
	authorizeCall  AuthorizeParams
	authorizeCalls int
	authorizeRes   AuthorizeResult
}

func (s *stubAccount) AccountID(ctx context.Context) (string, error) { return s.id, nil }
func (s *stubAccount) SignChallenge(ctx context.Context, codeChallenge string) (string, error) {
	return s.jwt, nil
}
func (s *stubAccount) SpendPermission(ctx context.Context, resourceURL string) (string, error) {
	return s.spendToken, nil
}
func (s *stubAccount) Authorize(ctx context.Context, p AuthorizeParams) (AuthorizeResult, error) {
	s.authorizeCall = p
	s.authorizeCalls++
	if s.authorizeErr != nil {
		return AuthorizeResult{}, s.authorizeErr
	}
	return s.authorizeRes, nil
}

func TestHybridAccountDelegatesIdentityAndPayments(t *testing.T) {
	identity := &stubAccount{id: "atxp:identity-account", jwt: "signed.jwt", spendToken: "spend-tok"}
	payments := &stubAccount{authorizeRes: AuthorizeResult{Protocol: "x402", Credential: "cred"}}
	h := &HybridAccount{Identity: identity, Payments: payments}

	ctx := context.Background()

	id, err := h.AccountID(ctx)
	if err != nil || id != "atxp:identity-account" {
		t.Errorf("AccountID = %q, %v; want identity's id", id, err)
	}

	jwt, err := h.SignChallenge(ctx, "challenge")
	if err != nil || jwt != "signed.jwt" {
		t.Errorf("SignChallenge = %q, %v; want identity's jwt", jwt, err)
	}

	tok, err := h.SpendPermission(ctx, "https://example.com")
	if err != nil || tok != "spend-tok" {
		t.Errorf("SpendPermission = %q, %v; want identity's token", tok, err)
	}

	res, err := h.Authorize(ctx, AuthorizeParams{Amount: "0.01"})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if res.Protocol != "x402" || res.Credential != "cred" {
		t.Errorf("Authorize result = %+v, want payments' result", res)
	}
	if payments.authorizeCall.Amount != "0.01" {
		t.Errorf("Authorize was called with %+v, want the same params passed to HybridAccount", payments.authorizeCall)
	}
	if identity.authorizeCalls != 0 {
		t.Error("Authorize should never be delegated to Identity")
	}

	payments.authorizeErr = errors.New("authorize failed")
	if _, err := h.Authorize(ctx, AuthorizeParams{}); err == nil {
		t.Error("expected Authorize to propagate the Payments account's error")
	}
}
