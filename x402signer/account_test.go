package x402signer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	atxp "github.com/justinstimatze/chit"
)

func testAccount(t *testing.T) *X402SignerAccount {
	t.Helper()
	acct, err := NewFromPrivateKeyHex(katPrivHex, "")
	if err != nil {
		t.Fatal(err)
	}
	return acct
}

func TestSelectExactAccept(t *testing.T) {
	reqs := x402PaymentRequirements{
		X402Version: 2,
		Accepts: []x402PaymentOption{
			{Scheme: "upto", Network: "eip155:8453", PayTo: "0xupto"},
			{Scheme: "exact", Network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", PayTo: "solrec"},
			{Scheme: "exact", Network: "eip155:8453", PayTo: "0xbase"},
			{Scheme: "exact", Network: "eip155:84532", PayTo: "0xbasesepolia"},
		},
	}

	got, err := selectExactAccept(reqs, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.PayTo != "0xbase" {
		t.Errorf("unpinned selection = %+v, want the first exact/eip155 accept (0xbase)", got)
	}

	got2, err := selectExactAccept(reqs, "eip155:84532")
	if err != nil {
		t.Fatal(err)
	}
	if got2.PayTo != "0xbasesepolia" {
		t.Errorf("pinned selection = %+v, want eip155:84532 (0xbasesepolia)", got2)
	}

	if _, err := selectExactAccept(reqs, "eip155:1"); err == nil {
		t.Error("pinning to an unoffered network should error, not silently fall through")
	}
}

func TestSelectExactAcceptNoneOffered(t *testing.T) {
	reqs := x402PaymentRequirements{Accepts: []x402PaymentOption{
		{Scheme: "upto", Network: "eip155:8453", PayTo: "0xupto"},
		{Scheme: "exact", Network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", PayTo: "solrec"},
	}}
	if _, err := selectExactAccept(reqs, ""); err == nil {
		t.Error("expected an error when only upto/solana accepts are offered")
	}
}

func TestAuthorizeCredentialShape(t *testing.T) {
	acct := testAccount(t)
	reqs := x402PaymentRequirements{
		X402Version: 2,
		Accepts: []x402PaymentOption{
			{
				Scheme: "exact", Network: "eip155:8453",
				Amount: "10000", // 0.01 USDC, atomic units
				PayTo:  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				Asset:  "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
				Extra:  map[string]any{"name": "USD Coin", "version": "2"},
			},
		},
	}
	raw, err := json.Marshal(reqs)
	if err != nil {
		t.Fatal(err)
	}

	res, err := acct.Authorize(context.Background(), atxp.AuthorizeParams{
		Protocols:           []string{"x402"},
		PaymentRequirements: raw,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Protocol != "x402" {
		t.Errorf("Protocol = %q, want x402", res.Protocol)
	}

	decoded, err := base64.StdEncoding.DecodeString(res.Credential)
	if err != nil {
		t.Fatalf("credential is not base64-std: %v", err)
	}
	var cred struct {
		X402Version int `json:"x402Version"`
		Accepted    struct {
			Network string `json:"network"`
			Scheme  string `json:"scheme"`
			Asset   string `json:"asset"`
			Amount  string `json:"amount"`
			PayTo   string `json:"payTo"`
		} `json:"accepted"`
		Payload struct {
			Signature     string `json:"signature"`
			Authorization struct {
				From, To, Value, ValidAfter, ValidBefore, Nonce string
			} `json:"authorization"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(decoded, &cred); err != nil {
		t.Fatalf("credential is not valid JSON: %v\nbody: %s", err, decoded)
	}
	if cred.X402Version != 2 {
		t.Errorf("x402Version = %d, want 2", cred.X402Version)
	}
	// accepted must carry the FULL matching PaymentRequirements (per the real
	// x402 v2 spec's PaymentPayload), not just {network, scheme} — a facilitator
	// needs the asset/amount/payTo terms to verify the signature against.
	if cred.Accepted.Network != "eip155:8453" || cred.Accepted.Scheme != "exact" ||
		cred.Accepted.Asset != "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" ||
		cred.Accepted.Amount != "10000" ||
		cred.Accepted.PayTo != "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" {
		t.Errorf("accepted = %+v", cred.Accepted)
	}
	if !strings.HasPrefix(cred.Payload.Signature, "0x") || len(cred.Payload.Signature) != 2+130 {
		t.Errorf("signature = %q, want 0x-prefixed 65-byte hex", cred.Payload.Signature)
	}
	if cred.Payload.Authorization.From != acct.Address() {
		t.Errorf("authorization.from = %q, want %q", cred.Payload.Authorization.From, acct.Address())
	}
	if cred.Payload.Authorization.To != "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" {
		t.Errorf("authorization.to = %q", cred.Payload.Authorization.To)
	}
	if cred.Payload.Authorization.Value != "10000" {
		t.Errorf("authorization.value = %q, want 10000 (atomic, unscaled)", cred.Payload.Authorization.Value)
	}
}

func TestAuthorizeRejectsNonX402Challenge(t *testing.T) {
	acct := testAccount(t)
	if _, err := acct.Authorize(context.Background(), atxp.AuthorizeParams{Protocols: []string{"atxp"}}); err == nil {
		t.Error("expected an error when the challenge carries no x402 paymentRequirements")
	}
}

// Regression: lock in the SignChallenge-errors / SpendPermission-returns-empty
// decision so a future refactor can't silently change it back to a no-op
// that lets oauth.go's authenticate() proceed with an empty Bearer JWT.
func TestSignChallengeReturnsError(t *testing.T) {
	acct := testAccount(t)
	if _, err := acct.SignChallenge(context.Background(), "challenge"); err == nil {
		t.Error("SignChallenge must error: this account cannot complete an OAuth handshake")
	}
}

func TestSpendPermissionReturnsEmpty(t *testing.T) {
	acct := testAccount(t)
	tok, err := acct.SpendPermission(context.Background(), "https://example.com/resource")
	if err != nil || tok != "" {
		t.Errorf("SpendPermission = (%q, %v), want (\"\", nil)", tok, err)
	}
}

func TestAccountIDIsAddress(t *testing.T) {
	acct := testAccount(t)
	id, err := acct.AccountID(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id != acct.Address() {
		t.Errorf("AccountID = %q, want Address() = %q", id, acct.Address())
	}
}

// Compile-time check that X402SignerAccount satisfies atxp.Account.
var _ atxp.Account = (*X402SignerAccount)(nil)
