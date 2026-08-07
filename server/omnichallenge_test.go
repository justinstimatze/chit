package server

import (
	"encoding/json"
	"testing"
	"time"
)

// fixedTime is a deterministic clock for Tempo expiry assertions.
var fixedTime = time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)

func mustAmount(t *testing.T, s string) Amount {
	t.Helper()
	a, err := ParseAmount(s)
	if err != nil {
		t.Fatalf("ParseAmount(%q): %v", s, err)
	}
	return a
}

func TestDataTablesVerbatim(t *testing.T) {
	// These constants point real money at real contracts; guard against an
	// accidental edit. Values transcribed from @atxp/common constants.ts.
	if USDCAddresses["base"] != "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" {
		t.Error("base USDC address drifted")
	}
	if USDCAddresses["solana"] != "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v" {
		t.Error("solana USDC mint drifted")
	}
	if CAIP2Networks["base"] != "eip155:8453" {
		t.Error("base CAIP2 drifted")
	}
	if CAIP2Networks["solana"] != "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" {
		t.Error("solana CAIP2 drifted")
	}
	if solanaFeePayers["solana"] != "BFK9TLC3edb13K6v4YyH3DwPb5DSUpkWvb7XnqCL9b4F" {
		t.Error("solana fee payer drifted")
	}
}

func TestBuildX402EVMAndSVM(t *testing.T) {
	amt := mustAmount(t, "0.01")
	opts := []chargeOption{
		{Network: "base", Currency: "USDC", Address: "0xabcDEF0000000000000000000000000000000001", Amount: amt},
		{Network: "solana", Currency: "USDC", Address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", Amount: amt},
	}
	req := buildX402Requirements(opts, "https://merchant.example/mcp", "Acme", nil)
	if req.X402Version != 2 {
		t.Errorf("x402Version = %d, want 2", req.X402Version)
	}
	if len(req.Accepts) != 2 {
		t.Fatalf("accepts len = %d, want 2", len(req.Accepts))
	}
	// EVM first.
	evm := req.Accepts[0]
	if evm.Network != "eip155:8453" {
		t.Errorf("evm network = %q", evm.Network)
	}
	if evm.Amount != "10000" {
		t.Errorf("evm amount = %q, want 10000 (micro-units)", evm.Amount)
	}
	if evm.Asset != USDCAddresses["base"] {
		t.Errorf("evm asset = %q", evm.Asset)
	}
	if evm.PayTo != "0xabcDEF0000000000000000000000000000000001" {
		t.Errorf("evm payTo = %q", evm.PayTo)
	}
	if evm.MaxTimeoutSeconds != 300 || evm.Scheme != "exact" {
		t.Errorf("evm scheme/timeout = %q/%d", evm.Scheme, evm.MaxTimeoutSeconds)
	}
	// SVM second.
	svm := req.Accepts[1]
	if svm.Network != "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" {
		t.Errorf("svm network = %q", svm.Network)
	}
	if fp, _ := svm.Extra["feePayer"].(string); fp != solanaFeePayers["solana"] {
		t.Errorf("svm feePayer = %q", fp)
	}
}

func TestBuildX402FiltersInvalidAddresses(t *testing.T) {
	amt := mustAmount(t, "0.01")
	// An EVM address not starting with 0x and an SVM address failing base58 must
	// both be dropped — never advertise a payTo we can't actually receive at.
	opts := []chargeOption{
		{Network: "base", Address: "not-hex", Amount: amt},
		{Network: "solana", Address: "0xnope", Amount: amt},
		{Network: "atxp", Address: "uuid-here", Amount: amt}, // non-x402 network
	}
	req := buildX402Requirements(opts, "r", "p", nil)
	if len(req.Accepts) != 0 {
		t.Errorf("accepts len = %d, want 0 (all filtered)", len(req.Accepts))
	}
}

func TestBuildMppSolanaAndTempo(t *testing.T) {
	amt := mustAmount(t, "0.01")
	opts := []chargeOption{
		{Network: "solana", Address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", Amount: amt},
		{Network: "tempo", Currency: "USDC", Address: "0xTempoRecipient", Amount: amt},
	}
	mpp := buildMppChallenges("pay-1", opts, "https://merchant.example/mcp", fixedTime, nil, nil)
	if len(mpp) != 2 {
		t.Fatalf("mpp len = %d, want 2", len(mpp))
	}
	sol, tempo := mpp[0], mpp[1]
	if sol.Method != "solana" || sol.Network != "mainnet-beta" {
		t.Errorf("solana method/network = %q/%q", sol.Method, sol.Network)
	}
	if sol.Amount != "10000" { // micro-units
		t.Errorf("solana amount = %q, want 10000", sol.Amount)
	}
	if sol.Currency != USDCAddresses["solana"] {
		t.Errorf("solana currency = %q", sol.Currency)
	}
	if tempo.Method != "tempo" || tempo.Amount != "0.01" { // human-readable
		t.Errorf("tempo method/amount = %q/%q, want tempo/0.01", tempo.Method, tempo.Amount)
	}
	if tempo.Expires != "2026-06-11T12:05:00.000Z" {
		t.Errorf("tempo expires = %q, want 2026-06-11T12:05:00.000Z", tempo.Expires)
	}
	if tempo.Resource == nil || tempo.Resource.URL != "https://merchant.example/mcp" {
		t.Errorf("tempo resource = %+v", tempo.Resource)
	}
}

func TestBuildMppNilWhenNoChains(t *testing.T) {
	amt := mustAmount(t, "0.01")
	opts := []chargeOption{{Network: "base", Address: "0xabc", Amount: amt}}
	if mpp := buildMppChallenges("pay-1", opts, "", fixedTime, nil, nil); mpp != nil {
		t.Errorf("expected nil mpp for base-only options, got %+v", mpp)
	}
}

func TestOmniChallengeMcpError(t *testing.T) {
	amt := mustAmount(t, "0.02")
	opts := []chargeOption{{Network: "base", Address: "0xabcDEF0000000000000000000000000000000001", Amount: amt}}
	x402 := buildX402Requirements(opts, "r", "p", nil)
	ch, err := omniChallengeMcpError("https://auth.atxp.ai", "pay-xyz", &amt, x402, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Code != -30402 {
		t.Errorf("code = %d, want -30402", ch.Code)
	}
	if ch.Data["paymentRequestUrl"] != "https://auth.atxp.ai/payment-request/pay-xyz" {
		t.Errorf("paymentRequestUrl = %v", ch.Data["paymentRequestUrl"])
	}
	if ch.Data["chargeAmount"] != "0.02" {
		t.Errorf("chargeAmount = %v, want 0.02", ch.Data["chargeAmount"])
	}
	// Data must be JSON-serializable for emission as a JSON-RPC error.
	if _, err := json.Marshal(ch.Data); err != nil {
		t.Fatalf("challenge data not serializable: %v", err)
	}
}

func TestBuildX402UptoAdvertisedWithFacilitatorAddress(t *testing.T) {
	amt := mustAmount(t, "0.01")
	opts := []chargeOption{
		{Network: "base", Currency: "USDC", Address: "0xabcDEF0000000000000000000000000000000001", Amount: amt},
	}
	facilitators := map[string]string{"eip155:8453": "0x7720030000000000000000000000000000000000"}

	req := buildX402Requirements(opts, "r", "p", facilitators)
	if len(req.Accepts) != 2 {
		t.Fatalf("accepts len = %d, want 2 (exact + upto)", len(req.Accepts))
	}
	if req.Accepts[0].Scheme != "exact" {
		t.Errorf("accepts[0].scheme = %q, want exact", req.Accepts[0].Scheme)
	}
	upto := req.Accepts[1]
	if upto.Scheme != "upto" || upto.Network != "eip155:8453" {
		t.Errorf("accepts[1] = %+v, want upto/eip155:8453", upto)
	}
	if fa, _ := upto.Extra["facilitatorAddress"].(string); fa != facilitators["eip155:8453"] {
		t.Errorf("upto facilitatorAddress = %q", fa)
	}
}

func TestBuildX402UptoOmittedWithoutFacilitatorAddress(t *testing.T) {
	amt := mustAmount(t, "0.01")
	opts := []chargeOption{{Network: "base", Address: "0xabcDEF0000000000000000000000000000000001", Amount: amt}}

	req := buildX402Requirements(opts, "r", "p", nil)
	if len(req.Accepts) != 1 || req.Accepts[0].Scheme != "exact" {
		t.Errorf("accepts = %+v, want exact-only", req.Accepts)
	}
}

func TestBuildX402DedupesBySchemeAndNetwork(t *testing.T) {
	amt := mustAmount(t, "0.01")
	// Same chain surfaced twice (two Base addresses) — keep only the first.
	opts := []chargeOption{
		{Network: "base", Address: "0xAddr1", Amount: amt},
		{Network: "base", Address: "0xAddr2", Amount: amt},
	}
	req := buildX402Requirements(opts, "r", "p", nil)
	if len(req.Accepts) != 1 || req.Accepts[0].PayTo != "0xAddr1" {
		t.Errorf("accepts = %+v, want one entry (0xAddr1)", req.Accepts)
	}
}

func TestBuildMppSessionChallenges(t *testing.T) {
	amt := mustAmount(t, "0.01")
	opts := []chargeOption{
		{Network: "solana", Address: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", Amount: amt},
		{Network: "tempo", Currency: "USDC", Address: "0xTempoRecipient", Amount: amt},
	}
	mpp := buildMppChallenges("pay-1", opts, "https://merchant.example/mcp", fixedTime,
		&MppSessionSupport{EscrowContract: "0xescrow", AuthorizedSigner: "0xsigner", Operator: "0xop", ChainID: 42},
		&SolanaMppSessionSupport{AuthorizedSigner: "solSigner"},
	)
	// solana charge, solana session, tempo charge, tempo session.
	if len(mpp) != 4 {
		t.Fatalf("mpp len = %d, want 4, got %+v", len(mpp), mpp)
	}
	solCharge, solSession, tempoCharge, tempoSessionCh := mpp[0], mpp[1], mpp[2], mpp[3]

	if solCharge.Intent != "charge" || solSession.Intent != "session" {
		t.Errorf("solana intents = %q/%q", solCharge.Intent, solSession.Intent)
	}
	solDetails, _ := solSession.Request["methodDetails"].(map[string]any)
	if got, _ := solDetails["authorizedSigner"].(string); got != "solSigner" {
		t.Errorf("solana session authorizedSigner = %q", got)
	}

	if tempoCharge.Intent != "charge" || tempoSessionCh.Intent != "session" {
		t.Errorf("tempo intents = %q/%q", tempoCharge.Intent, tempoSessionCh.Intent)
	}
	details, _ := tempoSessionCh.Request["methodDetails"].(map[string]any)
	if details["escrowContract"] != "0xescrow" || details["authorizedSigner"] != "0xsigner" || details["operator"] != "0xop" {
		t.Errorf("tempo session methodDetails = %+v", details)
	}
	if details["chainId"] != 42 {
		t.Errorf("tempo session chainId = %v, want 42", details["chainId"])
	}
}

func TestSerializeMppHeaderEscapes(t *testing.T) {
	c := MppChallengeData{
		Method: "solana", Intent: "charge", ID: `pay"injected`, Amount: "10000",
		Currency: "USDC", Network: "mainnet-beta", Recipient: "addr",
	}
	got := serializeMppHeader(c)
	want := `Payment method="solana", intent="charge", id="pay\"injected", amount="10000", currency="USDC", network="mainnet-beta", recipient="addr"`
	if got != want {
		t.Errorf("header = %q\nwant   %q", got, want)
	}
}
