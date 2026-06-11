package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testSettlement(authServer string, hc *http.Client) *ProtocolSettlement {
	return newProtocolSettlement(authServer, hc, "atxp:merchant", "test-app", nopLogger{})
}

func TestSettlementVerifyFailClosed(t *testing.T) {
	// A non-2xx verify must report invalid, never valid.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	ps := testSettlement(srv.URL, srv.Client())
	res, err := ps.Verify(context.Background(), ProtocolMPP, "eyJhIjoxfQ==", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("verify should be invalid on non-2xx (fail closed)")
	}
}

func TestSettlementSettleNon2xxErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	ps := testSettlement(srv.URL, srv.Client())
	if _, err := ps.Settle(context.Background(), ProtocolATXP, `{"sourceAccountId":"x"}`, nil); err == nil {
		t.Fatal("settle should error on non-2xx")
	}
}

func TestSettlementSettleSuccess(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(appNameHeader) != "test-app" {
			t.Errorf("app name header = %q", r.Header.Get(appNameHeader))
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"0.01"}`)
	}))
	defer srv.Close()
	ps := testSettlement(srv.URL, srv.Client())
	res, err := ps.Settle(context.Background(), ProtocolATXP, `{"sourceAccountId":"atxp:caller","sourceAccountToken":"tok","options":[]}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.TxHash == nil || *res.TxHash != "0xabc" || res.SettledAmount != "0.01" {
		t.Errorf("settle result = %+v", res)
	}
	// ATXP body must carry the credential's source + the merchant destination.
	if gotBody["sourceAccountId"] != "atxp:caller" {
		t.Errorf("sourceAccountId = %v", gotBody["sourceAccountId"])
	}
	if gotBody["destinationAccountId"] != "atxp:merchant" {
		t.Errorf("destinationAccountId = %v", gotBody["destinationAccountId"])
	}
}

func TestSettlementMPPBadCredentialErrors(t *testing.T) {
	ps := testSettlement("https://auth.example", http.DefaultClient)
	// Not valid base64 or raw JSON → buildRequestBody must error before any call.
	if _, err := ps.Settle(context.Background(), ProtocolMPP, "%%%not-json%%%", nil); err == nil {
		t.Fatal("expected error for unparseable MPP credential")
	}
}

func TestSelectX402RequirementByNetwork(t *testing.T) {
	ps := testSettlement("https://auth.example", http.DefaultClient)
	reqs := &X402PaymentRequirements{
		X402Version: 2,
		Accepts: []X402PaymentOption{
			{Network: "eip155:8453", PayTo: "0xbase"},
			{Network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", PayTo: "solrec"},
		},
	}
	// Payload naming a solana accepted network selects the SVM accept.
	payload := map[string]any{"accepted": map[string]any{"network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}}
	got := ps.selectX402Requirement(payload, reqs)
	if opt, ok := got.(X402PaymentOption); !ok || opt.PayTo != "solrec" {
		t.Errorf("selected = %+v, want solana accept", got)
	}
	// No accepted network → fall back to the EVM accept.
	got2 := ps.selectX402Requirement(map[string]any{}, reqs)
	if opt, ok := got2.(X402PaymentOption); !ok || opt.PayTo != "0xbase" {
		t.Errorf("fallback = %+v, want EVM accept", got2)
	}
}

func TestSettlementInvalidAppNameDropped(t *testing.T) {
	// An app name outside the allowed format is dropped rather than sent.
	ps := newProtocolSettlement("https://auth.example", http.DefaultClient, "atxp:m", "bad name with spaces!", nopLogger{})
	if ps.appName != "" {
		t.Errorf("invalid app name should be dropped, got %q", ps.appName)
	}
}
