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
