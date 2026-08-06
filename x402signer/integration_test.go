package x402signer

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	atxp "github.com/justinstimatze/chit"
)

// TestFullFlow_BareX402ThenPaid proves X402SignerAccount actually satisfies
// atxp.Account end to end through the unmodified root-package transport: a
// bare HTTP 402 x402 challenge (no OAuth 401 at all, matching what this
// self-custodial account can pay per its own SignChallenge boundary) →
// Authorize signs a credential → the retry carries X-Payment → 200.
func TestFullFlow_BareX402ThenPaid(t *testing.T) {
	acct := testAccount(t)

	paid := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if paid {
			io.WriteString(w, "paid ok")
			return
		}
		if h := r.Header.Get("X-Payment"); h != "" {
			paid = true
			io.WriteString(w, "paid ok")
			return
		}
		x402, _ := json.Marshal(x402PaymentRequirements{
			X402Version: 2,
			Accepts: []x402PaymentOption{{
				Scheme: "exact", Network: "eip155:8453",
				Amount: "10000",
				PayTo:  "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
				Asset:  "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
				Extra:  map[string]any{"name": "USD Coin", "version": "2"},
			}},
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		_ = json.NewEncoder(w).Encode(map[string]any{"x402": json.RawMessage(x402)})
	}))
	defer srv.Close()

	c, err := atxp.NewWithAccount(atxp.Config{}, acct)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.HTTPClient().Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "paid ok" {
		t.Fatalf("status=%d body=%q, want 200 \"paid ok\"", resp.StatusCode, body)
	}
	if !paid {
		t.Error("server never observed a payment header")
	}
}
