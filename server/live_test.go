//go:build serverlive

// Live merchant-side test against production ATXP. Run with a funded account:
//
//	ATXP_CONNECTION=<funded-account-connection-string> \
//	    go test -tags serverlive -run TestLive ./server/...
//
// It exercises the real authorization server end to end on the merchant side:
// dynamic client registration (a real client_id minted on auth.atxp.ai), an
// on-demand /charge that returns 402 because no caller token is supplied, and a
// real /payment-request — i.e. it issues a genuine omni-challenge.
//
// Full settlement of that challenge requires a paying caller, which is the
// client half of chit (proven in the root live_test.go's TestLivePaidPath).
// The two halves together cover challenge -> pay -> settle.
package server

import (
	"context"
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	atxp "github.com/justinstimatze/chit"
)

func liveConnection(t *testing.T) string {
	t.Helper()
	conn := os.Getenv("ATXP_CONNECTION")
	if conn == "" {
		t.Skip("ATXP_CONNECTION not set; skipping live merchant test")
	}
	return conn
}

// connectionToken extracts the wallet-grade connection_token from the connection
// string. It is read only to drive DCR; it is never logged.
func connectionToken(t *testing.T, conn string) string {
	t.Helper()
	u, err := url.Parse(conn)
	if err != nil {
		t.Fatalf("parse connection string: %v", err)
	}
	tok := u.Query().Get("connection_token")
	if tok == "" {
		t.Fatal("connection string missing connection_token")
	}
	return tok
}

func TestLiveIssuesRealChallenge(t *testing.T) {
	conn := liveConnection(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Resolve the merchant's own ATXP account id via /me (root client).
	acct, err := atxp.NewATXPAccount(conn, nil)
	if err != nil {
		t.Fatalf("NewATXPAccount: %v", err)
	}
	merchantID, err := acct.AccountID(ctx)
	if err != nil {
		var re *atxp.RestrictionError
		if errors.As(err, &re) {
			t.Skipf("account restricted (%s); use a funded account", re.Code)
		}
		t.Fatalf("resolve merchant account id: %v", err)
	}

	m, err := New(Config{
		Destination:     StaticDestination{ID: merchantID}, // atxp-native rail only
		ConnectionToken: connectionToken(t, conn),
		PayeeName:       "chit serverlive test",
	})
	if err != nil {
		t.Fatalf("New merchant: %v", err)
	}

	// No SourceAccountToken, so the on-demand /charge cannot pull funds and the
	// AS returns 402 — which drives a real /payment-request and a real challenge.
	ch, err := m.RequirePayment(ctx, PaymentRequest{
		Price:    mustAmount(t, "0.01"),
		User:     merchantID,
		Resource: "https://chit.example/serverlive",
	})
	if err != nil {
		t.Fatalf("RequirePayment (live): %v", err)
	}
	if ch == nil {
		// Would mean the charge unexpectedly settled with no caller token.
		t.Fatal("expected a payment challenge, got nil (charge settled unexpectedly)")
	}
	prID, _ := ch.Data["paymentRequestId"].(string)
	if prID == "" {
		t.Fatalf("challenge missing a real paymentRequestId: %+v", ch.Data)
	}
	t.Logf("live challenge issued: code=%d paymentRequestId=%s", ch.Code, prID)
}

// TestLiveOmniChallengeAdvertisesMeteredVariants confirms the merchant's
// buildOmniError path picks up the metered protocol variants — x402 "upto"
// (from GET /x402/supported) and MPP Tempo "session" (from GET
// /mpp/supported) — from the real authorization server, added after chit's
// initial merchant port. It moves no money: like TestLiveIssuesRealChallenge,
// there is no SourceAccountToken, so the on-demand charge 402s and this only
// issues (never pays) a challenge. The destination addresses are dummy
// (never actually paid to) — they exist purely so buildX402Requirements /
// buildMppChallenges have base/tempo options to attach the metered variant to.
func TestLiveOmniChallengeAdvertisesMeteredVariants(t *testing.T) {
	conn := liveConnection(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	acct, err := atxp.NewATXPAccount(conn, nil)
	if err != nil {
		t.Fatalf("NewATXPAccount: %v", err)
	}
	merchantID, err := acct.AccountID(ctx)
	if err != nil {
		var re *atxp.RestrictionError
		if errors.As(err, &re) {
			t.Skipf("account restricted (%s); use a funded account", re.Code)
		}
		t.Fatalf("resolve merchant account id: %v", err)
	}

	m, err := New(Config{
		Destination: StaticDestination{
			ID: merchantID,
			Addresses: []Source{
				{Chain: "base", Address: "0x000000000000000000000000000000DeaDBeef"},
				{Chain: "tempo", Address: "0x000000000000000000000000000000DeaDBeef"},
			},
		},
		ConnectionToken: connectionToken(t, conn),
		PayeeName:       "chit serverlive metered-variant test",
	})
	if err != nil {
		t.Fatalf("New merchant: %v", err)
	}

	ch, err := m.RequirePayment(ctx, PaymentRequest{
		Price:    mustAmount(t, "0.01"),
		User:     merchantID,
		Resource: "https://chit.example/serverlive-metered",
	})
	if err != nil {
		t.Fatalf("RequirePayment (live): %v", err)
	}
	if ch == nil {
		t.Fatal("expected a payment challenge, got nil (charge settled unexpectedly)")
	}

	var uptoSeen bool
	for _, a := range ch.X402.Accepts {
		t.Logf("x402 accept: scheme=%s network=%s", a.Scheme, a.Network)
		if a.Scheme == "upto" && a.Network == "eip155:8453" {
			uptoSeen = true
		}
	}
	if !uptoSeen {
		t.Error("expected an upto/eip155:8453 x402 accept (auth.atxp.ai/x402/supported advertises a base facilitator address as of this writing)")
	}

	var tempoSessionSeen bool
	for _, c := range ch.MPP {
		t.Logf("mpp challenge: method=%s intent=%s", c.Method, c.Intent)
		if c.Method == "tempo" && c.Intent == "session" {
			tempoSessionSeen = true
		}
	}
	if !tempoSessionSeen {
		t.Error("expected a tempo session-intent MPP challenge (auth.atxp.ai/mpp/supported advertises a Tempo settler as of this writing)")
	}
}

// TestLiveSettlesRealPayment exercises a real on-demand pull settlement: the
// authorization server pulls a (tiny) amount from a funded payer account and
// credits the merchant's destination account.
//
// Unlike TestLiveIssuesRealChallenge, THIS MOVES REAL MONEY. It is the only
// way to prove the merchant-side settle path end to end against production: a
// charge that returns 200 (charged==true), which RequirePayment reports as
// (nil, nil) — proceed.
//
// On-demand charging uses the "connection_token flow" (requirePayment.ts:29):
// the caller's token forwarded as sourceAccountToken IS the payer's
// connection_token (atxpAccount.ts injects this.token; types.ts:44 documents it
// as "User's OAuth token or connection_token"). So a direct pull needs only the
// payer's connection_token — no full client OAuth handshake.
//
// Env:
//
//	ATXP_CONNECTION        merchant/receiver account. Needs DCR (a valid
//	                       connection token); it need NOT be funded — receiving
//	                       does not require funds.
//	ATXP_PAYER_CONNECTION  funded payer account (the one actually charged). If
//	                       unset, the test self-charges using ATXP_CONNECTION as
//	                       both payer and payee — a path smoke test, though the
//	                       AS may treat source==destination specially.
//	ATXP_TEST_AMOUNT       amount to charge, default "0.01". Keep it tiny; real.
func TestLiveSettlesRealPayment(t *testing.T) {
	merchantConn := liveConnection(t)
	payerConn := os.Getenv("ATXP_PAYER_CONNECTION")
	selfCharge := payerConn == ""
	if selfCharge {
		payerConn = merchantConn
	}

	amtStr := os.Getenv("ATXP_TEST_AMOUNT")
	if amtStr == "" {
		amtStr = "0.01"
	}
	price := mustAmount(t, amtStr)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Resolve the payer account id and confirm it is not restricted — an
	// unfunded or fraud_blocked payer cannot be pulled from.
	payerAcct, err := atxp.NewATXPAccount(payerConn, nil)
	if err != nil {
		t.Fatalf("NewATXPAccount(payer): %v", err)
	}
	payerID, err := payerAcct.AccountID(ctx)
	if err != nil {
		var re *atxp.RestrictionError
		if errors.As(err, &re) {
			t.Skipf("payer account restricted (%s); use a funded account", re.Code)
		}
		t.Fatalf("resolve payer account id: %v", err)
	}

	// Resolve the merchant/receiver account id (same account in self-charge mode).
	merchantID := payerID
	if !selfCharge {
		merchantAcct, err := atxp.NewATXPAccount(merchantConn, nil)
		if err != nil {
			t.Fatalf("NewATXPAccount(merchant): %v", err)
		}
		merchantID, err = merchantAcct.AccountID(ctx)
		if err != nil {
			var re *atxp.RestrictionError
			if errors.As(err, &re) {
				t.Skipf("merchant account restricted (%s)", re.Code)
			}
			t.Fatalf("resolve merchant account id: %v", err)
		}
	}

	if selfCharge {
		t.Logf("WARNING: self-charge mode — payer == merchant == %s. "+
			"Set ATXP_PAYER_CONNECTION to a second account for a clean payer!=payee test.", merchantID)
	}

	m, err := New(Config{
		Destination:     StaticDestination{ID: merchantID},
		ConnectionToken: connectionToken(t, merchantConn),
		PayeeName:       "chit serverlive settle test",
	})
	if err != nil {
		t.Fatalf("New merchant: %v", err)
	}

	t.Logf("attempting on-demand pull of %s USDC: payer=%s -> merchant=%s", price.String(), payerID, merchantID)

	// SourceAccountToken is the payer's wallet-grade connection_token. It is
	// passed in-process to the AS over HTTPS and is never logged.
	ch, err := m.RequirePayment(ctx, PaymentRequest{
		Price:              price,
		User:               payerID,
		SourceAccountToken: connectionToken(t, payerConn),
		Resource:           "https://chit.example/serverlive-settle",
	})
	if err != nil {
		t.Fatalf("RequirePayment (settle): %v", err)
	}
	if ch != nil {
		// A challenge means the AS declined the on-demand pull (402) rather than
		// settling — the opposite of what this test asserts.
		prID, _ := ch.Data["paymentRequestId"].(string)
		t.Fatalf("expected an on-demand settlement, got a challenge (paymentRequestId=%s); "+
			"the AS did not pull-charge with the supplied payer token", prID)
	}
	t.Logf("SETTLED: pulled %s USDC from %s into %s", price.String(), payerID, merchantID)
}
