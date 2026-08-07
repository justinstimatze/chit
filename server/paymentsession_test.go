package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func sessionCredentialTempo(amountDecimal string) string {
	body, _ := json.Marshal(map[string]any{
		"challenge": map[string]any{"id": "ch_1", "method": "tempo", "intent": "session", "request": map[string]any{"amount": amountDecimal}},
		"payload":   map[string]any{"action": "voucher", "descriptor": map[string]any{"payer": "0x2", "payee": "0x1"}},
		"source":    "tempo:0xpayer",
	})
	return base64.StdEncoding.EncodeToString(body)
}

func chargeCredentialTempo(amountDecimal string) string {
	body, _ := json.Marshal(map[string]any{
		"challenge": map[string]any{"id": "ch_1", "method": "tempo", "request": map[string]any{"amount": amountDecimal}},
		"payload":   map[string]any{"action": "transaction", "transaction": "0xdeadbeef"},
		"source":    "tempo:0xpayer",
	})
	return base64.StdEncoding.EncodeToString(body)
}

func TestPaymentSessionChargeAccumulatesUnderCap(t *testing.T) {
	m := newTestMerchant(t, &fakePaymentServer{}, "")
	session := m.OpenPaymentSession(
		CredentialDetection{Protocol: ProtocolX402, Credential: base64.StdEncoding.EncodeToString([]byte(`{}`))},
		SettlementContext{PaymentRequirements: &X402PaymentRequirements{Accepts: []X402PaymentOption{{Amount: "1000000"}}}}, // 1.00 cap
	)
	if cap, unlimited := session.Cap(); unlimited || cap.String() != "1" {
		t.Fatalf("cap = %s unlimited=%v, want 1 (not unlimited)", cap.String(), unlimited)
	}
	if !session.Charge(mustAmount(t, "0.3")) {
		t.Fatal("charge 0.3 should succeed")
	}
	if !session.Charge(mustAmount(t, "0.2")) {
		t.Fatal("charge 0.2 should succeed")
	}
	if session.Spent().String() != "0.5" {
		t.Errorf("spent = %s, want 0.5", session.Spent().String())
	}
}

func TestPaymentSessionChargeRejectsOverCap(t *testing.T) {
	m := newTestMerchant(t, &fakePaymentServer{}, "")
	session := m.OpenPaymentSession(
		CredentialDetection{Protocol: ProtocolX402, Credential: base64.StdEncoding.EncodeToString([]byte(`{}`))},
		SettlementContext{PaymentRequirements: &X402PaymentRequirements{Accepts: []X402PaymentOption{{Amount: "500000"}}}}, // 0.50 cap
	)
	if !session.Charge(mustAmount(t, "0.4")) {
		t.Fatal("charge 0.4 should succeed (under the 0.5 cap)")
	}
	if session.Charge(mustAmount(t, "0.2")) {
		t.Fatal("charge 0.2 should fail: 0.4+0.2 > 0.5 cap")
	}
	if session.Spent().String() != "0.4" {
		t.Errorf("spent = %s, want 0.4 (rejected charge must not be recorded)", session.Spent().String())
	}
}

func TestPaymentSessionCapUnlimitedWhenUnparseable(t *testing.T) {
	m := newTestMerchant(t, &fakePaymentServer{}, "")
	session := m.OpenPaymentSession(
		CredentialDetection{Protocol: ProtocolATXP, Credential: `{"sourceAccountId":"atxp:x"}`}, // no amount anywhere
		SettlementContext{},
	)
	if _, unlimited := session.Cap(); !unlimited {
		t.Fatal("expected unlimited cap when the credential carries no derivable amount")
	}
	if !session.Charge(mustAmount(t, "999")) {
		t.Error("unlimited cap should accept any charge")
	}
}

func TestPaymentSessionDeriveCapMPPSolanaMicroUnits(t *testing.T) {
	credential := base64.StdEncoding.EncodeToString([]byte(`{"challenge":{"id":"ch","method":"solana","request":{"amount":"250000"}}}`))
	cap, unlimited := deriveSessionCap(ProtocolMPP, credential, SettlementContext{}, nopLogger{})
	if unlimited || cap.String() != "0.25" {
		t.Errorf("cap = %s unlimited=%v, want 0.25", cap.String(), unlimited)
	}
}

func TestPaymentSessionDeriveCapMPPTempoDecimalNoScaling(t *testing.T) {
	// Regression: dividing a Tempo decimal amount by 1e6 would under-scale the
	// cap to ~1e-9 and falsely re-challenge an already-paid Tempo request.
	credential := base64.StdEncoding.EncodeToString([]byte(`{"challenge":{"id":"ch","method":"tempo","request":{"amount":"0.001"}}}`))
	cap, unlimited := deriveSessionCap(ProtocolMPP, credential, SettlementContext{}, nopLogger{})
	if unlimited || cap.String() != "0.001" {
		t.Errorf("cap = %s unlimited=%v, want 0.001", cap.String(), unlimited)
	}
}

func TestPaymentSessionRequiresCloseOnlyForMPPSession(t *testing.T) {
	m := newTestMerchant(t, &fakePaymentServer{}, "")

	sessionSess := m.OpenPaymentSession(CredentialDetection{Protocol: ProtocolMPP, Credential: sessionCredentialTempo("0.01")}, SettlementContext{})
	if !sessionSess.requiresClose {
		t.Error("MPP session credential should set requiresClose")
	}

	chargeSess := m.OpenPaymentSession(CredentialDetection{Protocol: ProtocolMPP, Credential: chargeCredentialTempo("0.01")}, SettlementContext{})
	if chargeSess.requiresClose {
		t.Error("one-shot MPP charge credential should not set requiresClose")
	}

	atxpSess := m.OpenPaymentSession(CredentialDetection{Protocol: ProtocolATXP, Credential: `{"options":[{"amount":"0.01"}]}`}, SettlementContext{})
	if atxpSess.requiresClose {
		t.Error("ATXP credential should never set requiresClose")
	}
}

func newTestMerchantWithAuthServer(t *testing.T, authServer string, hc *http.Client) *Merchant {
	t.Helper()
	dest := StaticDestination{ID: "atxp:merchant-uuid"}
	m, err := New(Config{Destination: dest, AllowHTTP: true, AuthServer: authServer, HTTPClient: hc})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.now = func() time.Time { return fixedTime }
	m.opaque = fixedSigner(t)
	return m
}

func TestCloseSessionSettlesOnceForSpentAmount(t *testing.T) {
	var settleCalls int
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		settleCalls++
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"0.005"}`)
	}))
	defer srv.Close()

	m := newTestMerchantWithAuthServer(t, srv.URL, srv.Client())
	session := m.OpenPaymentSession(
		CredentialDetection{Protocol: ProtocolATXP, Credential: `{"sourceAccountId":"atxp:caller","options":[{"amount":"0.01"}]}`},
		SettlementContext{},
	)
	if !session.Charge(mustAmount(t, "0.005")) {
		t.Fatal("charge should succeed")
	}

	if err := m.CloseSession(context.Background(), session); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	// A second close must be a no-op.
	if err := m.CloseSession(context.Background(), session); err != nil {
		t.Fatalf("second CloseSession: %v", err)
	}
	if settleCalls != 1 {
		t.Errorf("settle calls = %d, want 1 (idempotent)", settleCalls)
	}
	options, _ := gotBody["options"].([]any)
	opt, _ := options[0].(map[string]any)
	if opt["amount"] != "0.005" {
		t.Errorf("settled amount = %v, want 0.005 (the spent actual, not the 0.01 cap)", opt["amount"])
	}
}

func TestCloseSessionExposesSettleResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"0.005"}`)
	}))
	defer srv.Close()

	m := newTestMerchantWithAuthServer(t, srv.URL, srv.Client())
	session := m.OpenPaymentSession(
		CredentialDetection{Protocol: ProtocolATXP, Credential: `{"sourceAccountId":"atxp:caller","options":[{"amount":"0.01"}]}`},
		SettlementContext{},
	)
	if _, ok := session.SettleResult(); ok {
		t.Fatal("SettleResult should report unset before Close")
	}
	if !session.Charge(mustAmount(t, "0.005")) {
		t.Fatal("charge should succeed")
	}
	if err := m.CloseSession(context.Background(), session); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	result, ok := session.SettleResult()
	if !ok {
		t.Fatal("SettleResult should report set after a successful Close")
	}
	if result.SettledAmount != "0.005" {
		t.Errorf("SettledAmount = %q, want 0.005. A caller must be able to check the REAL settled amount before crediting anything, not just that Close returned no error", result.SettledAmount)
	}
	if result.TxHash == nil || *result.TxHash != "0xabc" {
		t.Errorf("TxHash = %v, want 0xabc", result.TxHash)
	}
}

func TestCloseSessionFailsClosedOnUnderpayment(t *testing.T) {
	// The credential's self-reported accepted.amount matched the merchant's
	// advertised price ($0.01, so the local session.Charge cap check passed),
	// but the facilitator only actually settled $0.003, the x402 "exact"
	// scenario this whole check exists for.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"0.003"}`)
	}))
	defer srv.Close()

	m := newTestMerchantWithAuthServer(t, srv.URL, srv.Client())
	session := m.OpenPaymentSession(
		CredentialDetection{Protocol: ProtocolX402, Credential: base64.StdEncoding.EncodeToString([]byte(`{}`))},
		SettlementContext{PaymentRequirements: &X402PaymentRequirements{Accepts: []X402PaymentOption{{Amount: "10000"}}}}, // 0.01 cap
	)
	if !session.Charge(mustAmount(t, "0.01")) {
		t.Fatal("charge should succeed: 0.01 is within the 0.01 cap")
	}

	err := m.CloseSession(context.Background(), session)
	if err == nil {
		t.Fatal("CloseSession should fail closed: settled 0.003 is less than the 0.01 charged")
	}
	var underErr *UnderpaymentError
	if !errors.As(err, &underErr) {
		t.Fatalf("error = %v, want an *UnderpaymentError", err)
	}
	if underErr.Spent.String() != "0.01" || underErr.Settled.String() != "0.003" {
		t.Errorf("UnderpaymentError = {Spent:%s Settled:%s}, want {0.01 0.003}", underErr.Spent.String(), underErr.Settled.String())
	}

	// Real money moved and there's nothing to retry, so the session is
	// terminal. A second Close must still stay a no-op, not re-settle.
	if err := m.CloseSession(context.Background(), session); err != nil {
		t.Fatalf("second CloseSession should no-op, got: %v", err)
	}

	result, ok := session.SettleResult()
	if !ok || result.SettledAmount != "0.003" {
		t.Errorf("SettleResult should still be visible after an underpayment failure, got ok=%v result=%+v", ok, result)
	}
}

func TestCloseSessionFailsClosedOnUnparseableSettledAmount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"not-a-number"}`)
	}))
	defer srv.Close()

	m := newTestMerchantWithAuthServer(t, srv.URL, srv.Client())
	session := m.OpenPaymentSession(
		CredentialDetection{Protocol: ProtocolATXP, Credential: `{"sourceAccountId":"atxp:caller","options":[{"amount":"0.01"}]}`},
		SettlementContext{},
	)
	if !session.Charge(mustAmount(t, "0.01")) {
		t.Fatal("charge should succeed")
	}
	err := m.CloseSession(context.Background(), session)
	if err == nil {
		t.Fatal("CloseSession should fail closed on an unparseable settled amount, not assume it was enough")
	}
	var underErr *UnderpaymentError
	if !errors.As(err, &underErr) || underErr.ParseError == nil {
		t.Fatalf("error = %v, want an *UnderpaymentError with ParseError set", err)
	}
}

func TestCloseSessionNoopWhenNeverCharged(t *testing.T) {
	var settleCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		settleCalls++
		_, _ = io.WriteString(w, `{"txHash":"0xabc","settledAmount":"0"}`)
	}))
	defer srv.Close()

	m := newTestMerchantWithAuthServer(t, srv.URL, srv.Client())
	session := m.OpenPaymentSession(CredentialDetection{Protocol: ProtocolATXP, Credential: `{}`}, SettlementContext{})

	if err := m.CloseSession(context.Background(), session); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if settleCalls != 0 {
		t.Errorf("settle calls = %d, want 0 (never charged, not a channel session)", settleCalls)
	}
}

func TestCloseSessionSettlesChannelSessionEvenAtZeroSpend(t *testing.T) {
	var settleCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		settleCalls++
		_, _ = io.WriteString(w, `{"txHash":"0xclose","settledAmount":"0"}`)
	}))
	defer srv.Close()

	m := newTestMerchantWithAuthServer(t, srv.URL, srv.Client())
	session := m.OpenPaymentSession(CredentialDetection{Protocol: ProtocolMPP, Credential: sessionCredentialTempo("0.01")}, SettlementContext{})
	if session.Spent().String() != "0" {
		t.Fatal("session should start unspent")
	}

	if err := m.CloseSession(context.Background(), session); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if settleCalls != 1 {
		t.Errorf("settle calls = %d, want 1 (channel session must close/refund even at zero spend)", settleCalls)
	}
}

func TestCloseSessionLeavesChannelSessionUnsettledOnFailure(t *testing.T) {
	first := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if first {
			first = false
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"txHash":"0xclose","settledAmount":"0.003"}`)
	}))
	defer srv.Close()

	m := newTestMerchantWithAuthServer(t, srv.URL, srv.Client())
	session := m.OpenPaymentSession(CredentialDetection{Protocol: ProtocolMPP, Credential: sessionCredentialTempo("0.01")}, SettlementContext{})
	session.Charge(mustAmount(t, "0.003"))

	if err := m.CloseSession(context.Background(), session); err == nil {
		t.Fatal("expected the first (failing) settle to return an error")
	}
	session.mu.Lock()
	settled := session.settled
	session.mu.Unlock()
	if settled {
		t.Fatal("a failed channel-session settle must not be marked settled (deposit would be stranded)")
	}

	// A later re-drive succeeds.
	if err := m.CloseSession(context.Background(), session); err != nil {
		t.Fatalf("re-drive CloseSession: %v", err)
	}
}

func TestCloseSessionMarksOneShotSettledEvenOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m := newTestMerchantWithAuthServer(t, srv.URL, srv.Client())
	session := m.OpenPaymentSession(
		CredentialDetection{Protocol: ProtocolATXP, Credential: `{"options":[{"amount":"0.01"}]}`},
		SettlementContext{},
	)
	session.Charge(mustAmount(t, "0.005"))

	if err := m.CloseSession(context.Background(), session); err == nil {
		t.Fatal("expected the failing settle to return an error")
	}
	session.mu.Lock()
	settled := session.settled
	session.mu.Unlock()
	if !settled {
		t.Error("a one-shot credential must be marked settled even on failure (nothing to re-drive)")
	}
}
