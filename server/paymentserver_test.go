package server

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeCreds struct{ id, secret string }

func (f fakeCreds) clientCredentials(context.Context, string) (string, string, error) {
	return f.id, f.secret, nil
}

func newTestPaymentServer(t *testing.T, h http.HandlerFunc) (*ATXPPaymentServer, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	ps := newPaymentServer(srv.URL, srv.Client(), fakeCreds{"cid", "csecret"}, nopLogger{})
	return ps, srv
}

func sampleCharge() ChargeRequest {
	return ChargeRequest{
		Options:              []chargeOptionWire{{Network: "atxp", Currency: "USDC", Address: "uuid", Amount: "0.01"}},
		SourceAccountID:      "atxp:caller",
		DestinationAccountID: "atxp:merchant",
		PayeeName:            "Acme",
	}
}

func TestChargeStatusSemantics(t *testing.T) {
	cases := []struct {
		status    int
		wantPaid  bool
		wantError bool
	}{
		{http.StatusOK, true, false},               // synchronous settle
		{http.StatusAccepted, true, false},         // async accepted
		{http.StatusPaymentRequired, false, false}, // definitively unpaid
		{http.StatusInternalServerError, false, true},
		{http.StatusBadGateway, false, true},
		{http.StatusForbidden, false, true},
	}
	for _, c := range cases {
		ps, _ := newTestPaymentServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			_, _ = io.WriteString(w, `{"error":{"code":"X","message":"y"}}`)
		})
		paid, err := ps.Charge(context.Background(), sampleCharge())
		if (err != nil) != c.wantError {
			t.Errorf("status %d: err = %v, wantError %v", c.status, err, c.wantError)
		}
		if paid != c.wantPaid {
			t.Errorf("status %d: paid = %v, want %v", c.status, paid, c.wantPaid)
		}
	}
}

func TestChargeSendsBasicAuth(t *testing.T) {
	var gotAuth string
	ps, _ := newTestPaymentServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	if _, err := ps.Charge(context.Background(), sampleCharge()); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:csecret"))
	if gotAuth != want {
		t.Errorf("Authorization = %q, want %q", gotAuth, want)
	}
}

func TestCreatePaymentRequest(t *testing.T) {
	ps, _ := newTestPaymentServer(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/payment-request") {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"id":"pay-123"}`)
	})
	id, err := ps.CreatePaymentRequest(context.Background(), sampleCharge())
	if err != nil {
		t.Fatal(err)
	}
	if id != "pay-123" {
		t.Errorf("id = %q, want pay-123", id)
	}
}

func TestCreatePaymentRequestMissingID(t *testing.T) {
	ps, _ := newTestPaymentServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{}`)
	})
	if _, err := ps.CreatePaymentRequest(context.Background(), sampleCharge()); err == nil {
		t.Fatal("expected error when response lacks an id")
	}
}

func TestGetBalance(t *testing.T) {
	ps, _ := newTestPaymentServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"balance":"1.5"}`)
	})
	bal, err := ps.GetBalance(context.Background(), BalanceRequest{SourceAccountID: "a", DestinationAccountID: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if bal.String() != "1.5" {
		t.Errorf("balance = %s, want 1.5", bal.String())
	}
}

func TestChargeNetworkErrorFailsClosed(t *testing.T) {
	// A dead server (connection refused) must surface as an error, never as
	// (false, nil) which a caller could misread as a clean "unpaid".
	ps := newPaymentServer("http://127.0.0.1:1", &http.Client{}, fakeCreds{"c", "s"}, nopLogger{})
	paid, err := ps.Charge(context.Background(), sampleCharge())
	if err == nil {
		t.Fatal("expected error on network failure")
	}
	if paid {
		t.Fatal("paid should be false on network failure")
	}
}

func TestChargeMissingCredentialsFailsClosed(t *testing.T) {
	ps := newPaymentServer("https://auth.example", &http.Client{}, fakeCreds{"", ""}, nopLogger{})
	if _, err := ps.Charge(context.Background(), sampleCharge()); err == nil {
		t.Fatal("expected error when client credentials are missing")
	}
}
