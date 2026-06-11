package server

import (
	"context"
	"testing"
	"time"
)

// fakePaymentServer lets the gate tests drive charge/payment-request outcomes
// without a network.
type fakePaymentServer struct {
	chargePaid   bool
	chargeErr    error
	lastCharge   ChargeRequest
	createdID    string
	createErr    error
	lastCreate   ChargeRequest
	createCalled bool
}

func (f *fakePaymentServer) Charge(_ context.Context, req ChargeRequest) (bool, error) {
	f.lastCharge = req
	return f.chargePaid, f.chargeErr
}

func (f *fakePaymentServer) CreatePaymentRequest(_ context.Context, req ChargeRequest) (string, error) {
	f.createCalled = true
	f.lastCreate = req
	return f.createdID, f.createErr
}

func (f *fakePaymentServer) GetBalance(context.Context, BalanceRequest) (Amount, error) {
	return Amount{}, nil
}

// newTestMerchant builds a Merchant wired to a fake payment server, a fixed
// clock, and a deterministic opaque signer.
func newTestMerchant(t *testing.T, fps PaymentServer, min string) *Merchant {
	t.Helper()
	dest := StaticDestination{
		ID: "atxp:merchant-uuid",
		Addresses: []Source{
			{Chain: "base", Address: "0xMerchantBase0000000000000000000000000001"},
			{Chain: "solana", Address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"},
		},
	}
	cfg := Config{Destination: dest, AllowHTTP: true}
	if min != "" {
		cfg.MinimumPayment = mustAmount(t, min)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	m.paymentServer = fps
	m.now = func() time.Time { return fixedTime }
	m.opaque = fixedSigner(t)
	return m
}

func TestRequirePaymentChargeSucceeds(t *testing.T) {
	fps := &fakePaymentServer{chargePaid: true}
	m := newTestMerchant(t, fps, "")
	ch, err := m.RequirePayment(context.Background(), PaymentRequest{Price: mustAmount(t, "0.01"), User: "atxp:caller"})
	if err != nil {
		t.Fatal(err)
	}
	if ch != nil {
		t.Fatal("expected nil challenge when charge settles")
	}
	if fps.createCalled {
		t.Error("should not create a payment request when the charge settled")
	}
	// The merchant's own account is the charge source's destination.
	if fps.lastCharge.DestinationAccountID != "atxp:merchant-uuid" {
		t.Errorf("dest = %q", fps.lastCharge.DestinationAccountID)
	}
	if fps.lastCharge.SourceAccountID != "atxp:caller" {
		t.Errorf("source = %q", fps.lastCharge.SourceAccountID)
	}
}

func TestRequirePaymentChargeUnpaidBuildsChallenge(t *testing.T) {
	fps := &fakePaymentServer{chargePaid: false, createdID: "pay-987"}
	m := newTestMerchant(t, fps, "")
	ch, err := m.RequirePayment(context.Background(), PaymentRequest{
		Price: mustAmount(t, "0.01"), User: "atxp:caller", Resource: "https://merchant.example/mcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if ch == nil {
		t.Fatal("expected a challenge when charge is unpaid")
	}
	if !fps.createCalled {
		t.Error("should create a payment request when unpaid")
	}
	if ch.Data["paymentRequestId"] != "pay-987" {
		t.Errorf("paymentRequestId = %v", ch.Data["paymentRequestId"])
	}
	// Opaque identity must be injected into each MPP challenge and must verify.
	if len(ch.MPP) == 0 {
		t.Fatal("expected MPP challenges (solana source present)")
	}
	for _, c := range ch.MPP {
		sub, ok := m.opaque.verify(c.Opaque, c.ID)
		if !ok || sub != "atxp:caller" {
			t.Errorf("opaque on challenge %s did not verify to caller: sub=%q ok=%v", c.ID, sub, ok)
		}
	}
}

func TestRequirePaymentMinimumEnforced(t *testing.T) {
	// Price below the floor: the merchant must charge the floor, not the price.
	fps := &fakePaymentServer{chargePaid: true}
	m := newTestMerchant(t, fps, "0.05")
	_, err := m.RequirePayment(context.Background(), PaymentRequest{Price: mustAmount(t, "0.01"), User: "atxp:caller"})
	if err != nil {
		t.Fatal(err)
	}
	if got := fps.lastCharge.Options[0].Amount; got != "0.05" {
		t.Errorf("charged amount = %q, want 0.05 (the floor)", got)
	}
}

func TestRequirePaymentChargeErrorFailsClosed(t *testing.T) {
	// A charge that errors must NOT proceed and must NOT build a challenge as if
	// definitively unpaid — it surfaces the error so the caller denies.
	fps := &fakePaymentServer{chargeErr: context.DeadlineExceeded}
	m := newTestMerchant(t, fps, "")
	ch, err := m.RequirePayment(context.Background(), PaymentRequest{Price: mustAmount(t, "0.01"), User: "atxp:caller"})
	if err == nil {
		t.Fatal("expected error to propagate (fail closed)")
	}
	if ch != nil {
		t.Fatal("no challenge should be built on a charge error")
	}
	if fps.createCalled {
		t.Error("should not create a payment request on a charge error")
	}
}

func TestRequirePaymentRequiresUser(t *testing.T) {
	m := newTestMerchant(t, &fakePaymentServer{}, "")
	if _, err := m.RequirePayment(context.Background(), PaymentRequest{Price: mustAmount(t, "0.01")}); err == nil {
		t.Fatal("expected error when User is empty")
	}
}

func TestRequirePaymentExistingPaymentIDReused(t *testing.T) {
	fps := &fakePaymentServer{chargePaid: false}
	m := newTestMerchant(t, fps, "")
	ch, err := m.RequirePayment(context.Background(), PaymentRequest{
		Price: mustAmount(t, "0.01"), User: "atxp:caller",
		ExistingPaymentID: func(context.Context) (string, error) { return "pay-existing", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if ch == nil || ch.Data["paymentRequestId"] != "pay-existing" {
		t.Fatalf("expected reuse of existing payment id, got %+v", ch)
	}
	if fps.createCalled {
		t.Error("should not create a new payment request when an existing one is reused")
	}
}

func TestNewRejectsHugeMinimum(t *testing.T) {
	_, err := New(Config{Destination: StaticDestination{ID: "atxp:x"}, MinimumPayment: mustAmount(t, "1.01")})
	if err == nil {
		t.Fatal("expected error for MinimumPayment > $1.00")
	}
}

func TestNewRequiresDestination(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected error when Destination is nil")
	}
}
