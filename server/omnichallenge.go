package server

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Omni-challenge assembly. Ported from omniChallenge.ts. Given the merchant's
// destination chain addresses and a price, this builds the multi-rail payment
// challenge: x402 `accepts[]`, MPP challenges (Solana / Tempo), and the
// ATXP-native payment-request data, combined into one MCP error.

// base58Re matches a Solana address (base58, 32–44 chars). Ported from the
// inline regex in omniChallenge.ts buildX402Requirements.
var base58Re = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)

// caip2 returns the CAIP-2 identifier for a network, falling back to the network
// name itself (TS: `CAIP2_NETWORKS[net] || net`).
func caip2(network string) string {
	if v, ok := CAIP2Networks[network]; ok {
		return v
	}
	return network
}

// usdcAsset returns the USDC address for a network, falling back to fallbackNet's
// address (TS: `USDC_ADDRESSES[net] || USDC_ADDRESSES['base']`).
func usdcAsset(network, fallbackNet string) string {
	if v, ok := USDCAddresses[network]; ok {
		return v
	}
	return USDCAddresses[fallbackNet]
}

// buildX402Requirements builds x402 payment requirements from charge options.
// EVM (Base) options come first so a client with no chain preference uses the
// first entry. Ported from omniChallenge.ts buildX402Requirements.
func buildX402Requirements(options []chargeOption, resource, payeeName string) X402PaymentRequirements {
	accepts := []X402PaymentOption{}
	for _, o := range options {
		if x402EVMNetworks[o.Network] && strings.HasPrefix(o.Address, "0x") {
			accepts = append(accepts, X402PaymentOption{
				Scheme:            "exact",
				Network:           caip2(o.Network),
				Amount:            o.Amount.MicroString(),
				Resource:          resource,
				Description:       payeeName,
				MimeType:          "application/json",
				PayTo:             o.Address,
				MaxTimeoutSeconds: 300,
				Asset:             usdcAsset(o.Network, "base"),
				Extra:             map[string]any{"name": "USD Coin", "version": "2"},
			})
		}
	}
	for _, o := range options {
		if x402SVMNetworks[o.Network] && base58Re.MatchString(o.Address) {
			feePayer := solanaFeePayers[o.Network]
			if feePayer == "" {
				feePayer = solanaFeePayers["solana"]
			}
			accepts = append(accepts, X402PaymentOption{
				Scheme:            "exact",
				Network:           caip2(o.Network),
				Amount:            o.Amount.MicroString(),
				Resource:          resource,
				Description:       payeeName,
				MimeType:          "application/json",
				PayTo:             o.Address,
				MaxTimeoutSeconds: 300,
				Asset:             usdcAsset(o.Network, "solana"),
				Extra:             map[string]any{"feePayer": feePayer},
			})
		}
	}
	return X402PaymentRequirements{X402Version: 2, Accepts: accepts}
}

// buildMppChallenges builds one MPP challenge per supported chain (Solana and/or
// Tempo). Returns nil if no suitable option exists. Ported from omniChallenge.ts
// buildMppChallenges, including the per-chain amount-encoding asymmetry.
//
// now is injected (rather than read from the clock inside) so the Tempo expiry
// is testable and the function stays deterministic.
func buildMppChallenges(id string, options []chargeOption, resource string, now time.Time) []MppChallengeData {
	var challenges []MppChallengeData
	var resField *resourceRef
	if resource != "" {
		resField = &resourceRef{URL: resource}
	}

	// Solana: amount in micro-units (e.g. "10000" = 0.01 USDC); @solana/mpp
	// expects pre-converted micro-units.
	if sol, ok := findOption(options, "solana", "solana_devnet"); ok {
		isDevnet := sol.Network == "solana_devnet"
		currency := USDCAddresses["solana"]
		network := "mainnet-beta"
		if isDevnet {
			currency = USDCAddresses["solana_devnet"]
			network = "devnet"
		}
		micro := sol.Amount.MicroString()
		req := map[string]any{
			"amount":    micro,
			"currency":  currency,
			"recipient": sol.Address,
		}
		if resField != nil {
			req["resource"] = resField
		}
		challenges = append(challenges, MppChallengeData{
			ID:        id,
			Method:    "solana",
			Intent:    "charge",
			Amount:    micro,
			Currency:  currency,
			Network:   network,
			Recipient: sol.Address,
			Resource:  resField,
			Request:   req,
		})
	}

	// Tempo: amount in human-readable form (e.g. "0.01"); mppx calls
	// parseUnits(amount, decimals) internally. `expires` is required by mppx's
	// verify() for Tempo challenges.
	if tempo, ok := findOption(options, "tempo", "tempo_moderato"); ok {
		currency := tempo.Currency
		if currency == "" {
			currency = "USDC"
		}
		human := tempo.Amount.String()
		req := map[string]any{
			"amount":    human,
			"currency":  currency,
			"recipient": tempo.Address,
		}
		if resField != nil {
			req["resource"] = resField
		}
		challenges = append(challenges, MppChallengeData{
			ID:        id,
			Method:    "tempo",
			Intent:    "charge",
			Amount:    human,
			Currency:  currency,
			Network:   tempo.Network,
			Recipient: tempo.Address,
			Expires:   now.Add(5 * time.Minute).UTC().Format("2006-01-02T15:04:05.000Z07:00"),
			Resource:  resField,
			Request:   req,
		})
	}

	if len(challenges) == 0 {
		return nil
	}
	return challenges
}

func findOption(options []chargeOption, networks ...string) (chargeOption, bool) {
	want := map[string]bool{}
	for _, n := range networks {
		want[n] = true
	}
	for _, o := range options {
		if want[o.Network] {
			return o, true
		}
	}
	return chargeOption{}, false
}

// buildAtxpMcpChallenge builds the ATXP-native challenge data. Ported from
// omniChallenge.ts buildAtxpMcpChallenge.
func buildAtxpMcpChallenge(server, paymentRequestID string, chargeAmount *Amount) (AtxpMcpChallengeData, error) {
	u, err := url.Parse(server)
	if err != nil {
		return AtxpMcpChallengeData{}, fmt.Errorf("atxp server: parse server url %q: %w", server, err)
	}
	origin := u.Scheme + "://" + u.Host
	d := AtxpMcpChallengeData{
		PaymentRequestID:  paymentRequestID,
		PaymentRequestURL: origin + "/payment-request/" + paymentRequestID,
	}
	if chargeAmount != nil {
		d.ChargeAmount = chargeAmount.String()
	}
	return d, nil
}

// sourcesToOptions converts destination sources into internal charge options at
// a fixed amount. Ported from omniChallenge.ts sourcesToOptions.
func sourcesToOptions(sources []Source, amount Amount, currency string) []chargeOption {
	if currency == "" {
		currency = "USDC"
	}
	opts := make([]chargeOption, 0, len(sources))
	for _, s := range sources {
		opts = append(opts, chargeOption{
			Network:  s.Chain,
			Currency: currency,
			Address:  s.Address,
			Amount:   amount,
		})
	}
	return opts
}

// paymentOptions is the result of buildPaymentOptions — the protocol-specific
// challenge data for a given (amount, sources). Ported from the return shape of
// omniChallenge.ts buildPaymentOptions.
type paymentOptions struct {
	x402    X402PaymentRequirements
	mpp     []MppChallengeData
	options []chargeOption
}

// buildPaymentOptions is the single source of truth for "given chain addresses +
// amount, what do the protocol challenges look like?" Ported from
// omniChallenge.ts buildPaymentOptions. challengeID must be provided (the
// payment request id); now seeds the Tempo expiry.
func buildPaymentOptions(amount Amount, sources []Source, resource, payeeName, challengeID string, now time.Time) paymentOptions {
	options := sourcesToOptions(sources, amount, "USDC")
	return paymentOptions{
		x402:    buildX402Requirements(options, resource, payeeName),
		mpp:     buildMppChallenges(challengeID, options, resource, now),
		options: options,
	}
}

// Challenge is a built omni-challenge ready to be returned to a caller as a
// JSON-RPC / MCP error. Code and Message are the MCP error fields; Data is the
// error.data object carrying all three protocols' challenge data.
type Challenge struct {
	Code    int
	Message string
	Data    map[string]any

	// Structured views of the same data, for callers that want typed access
	// (e.g. to emit an HTTP 402 instead of an MCP error).
	AtxpMcp AtxpMcpChallengeData
	X402    X402PaymentRequirements
	MPP     []MppChallengeData
}

// omniChallengeMcpError assembles the omni-challenge MCP error. Ported from
// omniChallenge.ts omniChallengeMcpError. Uses the legacy code -30402 for
// backwards compatibility (old clients only recognize -30402).
func omniChallengeMcpError(server, paymentRequestID string, chargeAmount *Amount, x402 X402PaymentRequirements, mpp []MppChallengeData) (*Challenge, error) {
	atxpMcp, err := buildAtxpMcpChallenge(server, paymentRequestID, chargeAmount)
	if err != nil {
		return nil, err
	}

	data := map[string]any{
		"paymentRequestId":  atxpMcp.PaymentRequestID,
		"paymentRequestUrl": atxpMcp.PaymentRequestURL,
		"x402":              x402,
	}
	if atxpMcp.ChargeAmount != "" {
		data["chargeAmount"] = atxpMcp.ChargeAmount
	}
	if len(mpp) > 0 {
		data["mpp"] = mpp
	}

	amountText := ""
	if chargeAmount != nil {
		amountText = " You will be charged " + chargeAmount.String() + "."
	}
	message := paymentRequiredPreamble + amountText +
		" Please pay at: " + atxpMcp.PaymentRequestURL + " and then try again."

	return &Challenge{
		Code:    paymentRequiredErrorCode,
		Message: message,
		Data:    data,
		AtxpMcp: atxpMcp,
		X402:    x402,
		MPP:     mpp,
	}, nil
}

// serializeMppHeader serializes one MPP challenge into a WWW-Authenticate:
// Payment header value, escaping double quotes to prevent header injection.
// Ported from omniChallenge.ts serializeMppHeader.
func serializeMppHeader(c MppChallengeData) string {
	esc := func(v string) string { return strings.ReplaceAll(v, `"`, `\"`) }
	base := fmt.Sprintf(
		`Payment method="%s", intent="%s", id="%s", amount="%s", currency="%s", network="%s", recipient="%s"`,
		esc(c.Method), esc(c.Intent), esc(c.ID), esc(c.Amount), esc(c.Currency), esc(c.Network), esc(c.Recipient),
	)
	if c.Expires != "" {
		base += fmt.Sprintf(`, expires="%s"`, esc(c.Expires))
	}
	return base
}
