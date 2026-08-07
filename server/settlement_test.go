package server

import (
	"context"
	"encoding/base64"
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
	if _, err := ps.Settle(context.Background(), ProtocolATXP, `{"sourceAccountId":"x"}`, nil, nil); err == nil {
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
	res, err := ps.Settle(context.Background(), ProtocolATXP, `{"sourceAccountId":"atxp:caller","sourceAccountToken":"tok","options":[]}`, nil, nil)
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
	if _, err := ps.Settle(context.Background(), ProtocolMPP, "%%%not-json%%%", nil, nil); err == nil {
		t.Fatal("expected error for unparseable MPP credential")
	}
}

func TestSelectX402AcceptByNetwork(t *testing.T) {
	reqs := &X402PaymentRequirements{
		X402Version: 2,
		Accepts: []X402PaymentOption{
			{Network: "eip155:8453", PayTo: "0xbase"},
			{Network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", PayTo: "solrec"},
		},
	}
	// Payload naming a solana accepted network selects the SVM accept.
	payload := map[string]any{"accepted": map[string]any{"network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}}
	got := selectX402Accept(payload, reqs, nil)
	if got == nil || got.PayTo != "solrec" {
		t.Errorf("selected = %+v, want solana accept", got)
	}
	// No accepted network → fall back to the EVM accept.
	got2 := selectX402Accept(map[string]any{}, reqs, nil)
	if got2 == nil || got2.PayTo != "0xbase" {
		t.Errorf("fallback = %+v, want EVM accept", got2)
	}
}

func TestSelectX402AcceptMatchesScheme(t *testing.T) {
	// One network advertising both exact and upto: a payload naming upto must
	// select the upto accept, not exact-first.
	reqs := &X402PaymentRequirements{
		X402Version: 2,
		Accepts: []X402PaymentOption{
			{Network: "eip155:8453", Scheme: "exact", Amount: "10000"},
			{Network: "eip155:8453", Scheme: "upto", Amount: "10000"},
		},
	}
	payload := map[string]any{"accepted": map[string]any{"network": "eip155:8453", "scheme": "upto"}}
	got := selectX402Accept(payload, reqs, nil)
	if got == nil || got.Scheme != "upto" {
		t.Errorf("selected = %+v, want upto accept", got)
	}
}

func TestSettleX402UptoSetsSettlementOverridesClampedToCap(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"3000"}`)
	}))
	defer srv.Close()
	ps := testSettlement(srv.URL, srv.Client())

	credential := base64.StdEncoding.EncodeToString([]byte(`{"signature":"0xabc"}`))
	sctx := &SettlementContext{PaymentRequirements: &X402PaymentRequirements{
		X402Version: 2,
		Accepts:     []X402PaymentOption{{Network: "eip155:8453", Scheme: "upto", Amount: "10000"}},
	}}
	// Metered actual ($0.003 = 3000µ) is under the cap (10000µ) — settle the actual.
	actual := mustAmount(t, "0.003")
	if _, err := ps.Settle(context.Background(), ProtocolX402, credential, sctx, &actual); err != nil {
		t.Fatal(err)
	}
	overrides, _ := gotBody["settlementOverrides"].(map[string]any)
	if overrides["amount"] != "3000" {
		t.Errorf("settlementOverrides.amount = %v, want 3000", overrides["amount"])
	}

	// A metered overshoot ($0.02 = 20000µ > the 10000µ cap) clamps to the cap.
	overshoot := mustAmount(t, "0.02")
	if _, err := ps.Settle(context.Background(), ProtocolX402, credential, sctx, &overshoot); err != nil {
		t.Fatal(err)
	}
	overrides, _ = gotBody["settlementOverrides"].(map[string]any)
	if overrides["amount"] != "10000" {
		t.Errorf("settlementOverrides.amount = %v, want 10000 (clamped)", overrides["amount"])
	}
}

func TestSettleX402ExactOmitsSettlementOverrides(t *testing.T) {
	// exact/EIP-3009 commits the signature to a fixed value; overriding the
	// amount would mismatch the signed authorization and get rejected.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"10000"}`)
	}))
	defer srv.Close()
	ps := testSettlement(srv.URL, srv.Client())

	credential := base64.StdEncoding.EncodeToString([]byte(`{"signature":"0xabc"}`))
	sctx := &SettlementContext{PaymentRequirements: &X402PaymentRequirements{
		X402Version: 2,
		Accepts:     []X402PaymentOption{{Network: "eip155:8453", Scheme: "exact", Amount: "10000"}},
	}}
	body, err := ps.buildRequestBody(ProtocolX402, credential, sctx, ptrAmount(mustAmount(t, "0.003")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := body["settlementOverrides"]; ok {
		t.Errorf("exact scheme must not carry settlementOverrides, got %v", body["settlementOverrides"])
	}
}

func TestSettleMppSessionSetsSettlementOverrides(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = io.WriteString(w, `{"txHash":"0xmpp","settledAmount":"3000"}`)
	}))
	defer srv.Close()
	ps := testSettlement(srv.URL, srv.Client())

	sessionCred := base64.RawURLEncoding.EncodeToString([]byte(`{
		"challenge": {"id":"ch","method":"tempo","intent":"session","request":{"amount":"0.01"}},
		"payload": {"action":"voucher","descriptor":{"payer":"0x2","payee":"0x1"}},
		"source": "tempo:0xpayer"
	}`))
	actual := mustAmount(t, "0.003")
	if _, err := ps.Settle(context.Background(), ProtocolMPP, sessionCred, nil, &actual); err != nil {
		t.Fatal(err)
	}
	overrides, _ := gotBody["settlementOverrides"].(map[string]any)
	if overrides["amount"] != "3000" {
		t.Errorf("settlementOverrides.amount = %v, want 3000", overrides["amount"])
	}
}

func TestSettleMppChargeOmitsSettlementOverrides(t *testing.T) {
	// A one-shot `charge` credential settles the pre-signed transfer as-is;
	// actualAmount must not become a settlementOverrides.amount.
	chargeCred := base64.RawURLEncoding.EncodeToString([]byte(`{
		"challenge": {"id":"ch","method":"tempo","intent":"charge","request":{"amount":"0.01"}},
		"payload": {"action":"transaction","transaction":"0xdeadbeef"},
		"source": "tempo:0xpayer"
	}`))
	ps := testSettlement("https://auth.example", http.DefaultClient)
	body, err := ps.buildRequestBody(ProtocolMPP, chargeCred, nil, ptrAmount(mustAmount(t, "0.003")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := body["settlementOverrides"]; ok {
		t.Errorf("one-shot mpp charge must not carry settlementOverrides, got %v", body["settlementOverrides"])
	}
}

func TestSettleATXPActualAmountOverridesOptions(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"0.003"}`)
	}))
	defer srv.Close()
	ps := testSettlement(srv.URL, srv.Client())

	credential := `{"sourceAccountId":"atxp:caller","sourceAccountToken":"tok","options":[{"amount":"0.01","network":"base"}]}`
	actual := mustAmount(t, "0.003")
	if _, err := ps.Settle(context.Background(), ProtocolATXP, credential, nil, &actual); err != nil {
		t.Fatal(err)
	}
	options, _ := gotBody["options"].([]any)
	if len(options) != 1 {
		t.Fatalf("options = %+v, want 1 entry", options)
	}
	opt, _ := options[0].(map[string]any)
	if opt["amount"] != "0.003" {
		t.Errorf("option amount = %v, want 0.003 (the actual, not the cap)", opt["amount"])
	}
	if opt["network"] != "base" {
		t.Errorf("option network = %v, want preserved as base", opt["network"])
	}
}

func ptrAmount(a Amount) *Amount { return &a }

// A concretely-typed Options slice is a plausible caller shape — the field is
// declared `any` specifically so callers aren't forced into []any/map[string]any.
// Regression: overrideOptionsAmount used to type-assert options.([]any) directly,
// which silently no-ops for any other slice type, settling the credential's full
// authorized cap instead of the metered actual with no warning logged.
type reproTypedOption struct {
	Network string `json:"network"`
	Amount  string `json:"amount"`
}

func TestSettleATXPActualAmountOverridesTypedOptionsSlice(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"0.003"}`)
	}))
	defer srv.Close()
	ps := testSettlement(srv.URL, srv.Client())

	sctx := &SettlementContext{Options: []reproTypedOption{{Network: "base", Amount: "0.01"}}}
	actual := mustAmount(t, "0.003") // metered actual, under the 0.01 cap
	if _, err := ps.Settle(context.Background(), ProtocolATXP, `{"sourceAccountId":"atxp:caller"}`, sctx, &actual); err != nil {
		t.Fatal(err)
	}
	options, _ := gotBody["options"].([]any)
	if len(options) != 1 {
		t.Fatalf("options = %+v, want 1 entry", options)
	}
	opt, _ := options[0].(map[string]any)
	if opt["amount"] != "0.003" {
		t.Errorf("option amount = %v, want 0.003 (the actual, not the 0.01 cap)", opt["amount"])
	}
	if opt["network"] != "base" {
		t.Errorf("option network = %v, want preserved as base", opt["network"])
	}
}

func TestSettlementInvalidAppNameDropped(t *testing.T) {
	// An app name outside the allowed format is dropped rather than sent.
	ps := newProtocolSettlement("https://auth.example", http.DefaultClient, "atxp:m", "bad name with spaces!", nopLogger{})
	if ps.appName != "" {
		t.Errorf("invalid app name should be dropped, got %q", ps.appName)
	}
}
