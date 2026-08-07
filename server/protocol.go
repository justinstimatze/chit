package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Protocol identifies one of the three inbound payment rails. Ported from
// @atxp/common PaymentProtocolEnum.
type Protocol string

const (
	ProtocolATXP Protocol = "atxp"
	ProtocolX402 Protocol = "x402"
	ProtocolMPP  Protocol = "mpp"
)

// Source is a destination chain address the merchant can receive USDC at. Ported
// from the @atxp/common Source shape (only the fields the challenge builder uses).
type Source struct {
	Chain   string `json:"chain"`
	Address string `json:"address"`
}

// chargeOption is the internal per-network option used to build challenges.
// Mirrors the `{ network, currency, address, amount }` objects in omniChallenge.ts.
type chargeOption struct {
	Network  string
	Currency string
	Address  string
	Amount   Amount
}

// MppChallengeData is one MPP challenge (one supported chain). JSON tags match
// the wire shape in protocol.ts so the emitted `data.mpp[]` is identical to the
// reference SDK.
//
// The `amount` encoding is chain-dependent (see omnichallenge.go):
//   - method "solana": micro-units integer string, e.g. "10000"
//   - method "tempo":  human-readable decimal string, e.g. "0.01"
type MppChallengeData struct {
	ID        string         `json:"id"`
	Method    string         `json:"method"`
	Intent    string         `json:"intent"`
	Amount    string         `json:"amount"`
	Currency  string         `json:"currency"`
	Network   string         `json:"network"`
	Recipient string         `json:"recipient"`
	Expires   string         `json:"expires,omitempty"`
	Resource  *resourceRef   `json:"resource,omitempty"`
	Request   map[string]any `json:"request,omitempty"`
	Opaque    map[string]any `json:"opaque,omitempty"`
}

type resourceRef struct {
	URL string `json:"url"`
}

// X402PaymentOption is one entry of an x402 `accepts` array. Ported from
// protocol.ts X402PaymentOption.
type X402PaymentOption struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"`
	Amount            string         `json:"amount"`
	Resource          string         `json:"resource"`
	Description       string         `json:"description"`
	MimeType          string         `json:"mimeType,omitempty"`
	PayTo             string         `json:"payTo"`
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds,omitempty"`
	Asset             string         `json:"asset,omitempty"`
	Extra             map[string]any `json:"extra,omitempty"`
}

// X402PaymentRequirements is the x402 challenge body. Ported from protocol.ts.
type X402PaymentRequirements struct {
	X402Version int                 `json:"x402Version"`
	Accepts     []X402PaymentOption `json:"accepts"`
}

// AtxpMcpChallengeData is the ATXP-native portion of a challenge. Ported from
// protocol.ts AtxpMcpChallengeData.
type AtxpMcpChallengeData struct {
	PaymentRequestID  string `json:"paymentRequestId"`
	PaymentRequestURL string `json:"paymentRequestUrl"`
	ChargeAmount      string `json:"chargeAmount,omitempty"`
}

// CredentialDetection is the result of sniffing a retry request's headers for a
// payment credential. Ported from protocol.ts CredentialDetection.
type CredentialDetection struct {
	Protocol         Protocol
	Credential       string
	PaymentRequestID string
}

// DetectProtocol inspects inbound request headers on a retry and reports which
// payment rail (if any) the caller used. Ported from protocol.ts detectProtocol.
//
// Header precedence is preserved exactly: X-ATXP-PAYMENT (atxp) >
// PAYMENT-SIGNATURE/X-PAYMENT (x402) > Authorization: Payment (mpp).
//
// h.Get is case-insensitive (net/http canonicalizes header keys), matching the
// lowercased keys the TS version reads.
func DetectProtocol(h interface{ Get(string) string }) *CredentialDetection {
	paymentRequestID := h.Get("X-ATXP-Payment-Request-Id")

	if v := h.Get("X-ATXP-Payment"); v != "" {
		return &CredentialDetection{Protocol: ProtocolATXP, Credential: v, PaymentRequestID: paymentRequestID}
	}
	sig := h.Get("Payment-Signature")
	if sig == "" {
		sig = h.Get("X-Payment")
	}
	if sig != "" {
		return &CredentialDetection{Protocol: ProtocolX402, Credential: sig, PaymentRequestID: paymentRequestID}
	}
	if auth := h.Get("Authorization"); strings.HasPrefix(auth, "Payment ") {
		return &CredentialDetection{
			Protocol:         ProtocolMPP,
			Credential:       strings.TrimPrefix(auth, "Payment "),
			PaymentRequestID: paymentRequestID,
		}
	}
	return nil
}

// ExtractX402PayerAddress returns the actual signing address from an x402
// credential's authorization.from field. Unlike a PaymentRequest's User field
// (sourceAccountId), this address is cryptographically tied to the EIP-3009
// signature and cannot be forged, so it is the right thing to rate-limit,
// cap spend on, or blocklist against on the merchant's own side.
//
// See docs/PROTOCOL.md's fraud-block bypass note: ATXP's account-standing
// checks (fraud_blocked, etc.) are not enforced on sourceAccountId for the
// x402 settlement path, so merchants that need their own abuse protection
// should gate on this address, not on anything from PaymentRequest.User.
//
// Returns an error if the credential is not a parseable x402 credential or
// carries no authorization.from field (e.g. it is not the "exact" scheme).
func ExtractX402PayerAddress(credential string) (string, error) {
	payload := parseCredentialJSON(credential)
	if payload == nil {
		return "", fmt.Errorf("server: credential is not valid base64 or raw JSON")
	}
	inner, ok := payload["payload"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("server: credential has no payload field (not an x402 v2 credential)")
	}
	auth, ok := inner["authorization"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("server: credential's payload has no authorization field")
	}
	from, _ := auth["from"].(string)
	if from == "" {
		return "", fmt.Errorf("server: credential's authorization has no from address")
	}
	return from, nil
}

// parseCredentialJSON parses a credential that may be base64-encoded JSON or raw
// JSON. Ported from protocol.ts parseCredentialBase64. Returns nil if neither
// decoding yields a JSON object.
func parseCredentialJSON(credential string) map[string]any {
	if dec, err := base64.StdEncoding.DecodeString(credential); err == nil {
		var obj map[string]any
		if json.Unmarshal(dec, &obj) == nil && obj != nil {
			return obj
		}
	}
	// base64url without padding is also used for MPP credentials.
	if dec, err := base64.RawURLEncoding.DecodeString(credential); err == nil {
		var obj map[string]any
		if json.Unmarshal(dec, &obj) == nil && obj != nil {
			return obj
		}
	}
	var obj map[string]any
	if json.Unmarshal([]byte(credential), &obj) == nil && obj != nil {
		return obj
	}
	return nil
}

// isMppSessionCredential reports whether an MPP credential is a TIP-1034
// *session* (an on-chain payment channel opened at authorize) rather than a
// one-shot "charge". The authoritative signal is challenge.intent=="session";
// a channel descriptor on the payload is a structural backstop. Shared by the
// settle-body builder and PaymentSession so both classify a credential
// identically. Ported from protocol.ts isMppSessionCredential.
func isMppSessionCredential(credential string) bool {
	parsed := parseCredentialJSON(credential)
	if parsed == nil {
		return false
	}
	if challenge, ok := parsed["challenge"].(map[string]any); ok {
		if intent, _ := challenge["intent"].(string); intent == "session" {
			return true
		}
	}
	if payload, ok := parsed["payload"].(map[string]any); ok {
		if _, ok := payload["descriptor"]; ok {
			return true
		}
	}
	return false
}

// selectX402Accept picks the single accept matching the credential's chain
// (and, when advertised, scheme) from a full X402PaymentRequirements. logger
// may be nil (deriveSessionCap has no settlement-bound logger). Ported from
// the x402 branch of protocol.ts ProtocolSettlement.buildRequestBody.
func selectX402Accept(payload map[string]any, reqs *X402PaymentRequirements, logger Logger) *X402PaymentOption {
	if reqs == nil || len(reqs.Accepts) == 0 {
		return nil
	}
	accepts := reqs.Accepts

	var acceptedNetwork, acceptedScheme string
	if acc, ok := payload["accepted"].(map[string]any); ok {
		acceptedNetwork, _ = acc["network"].(string)
		acceptedScheme, _ = acc["scheme"].(string)
	}

	if acceptedNetwork != "" {
		// Match network AND scheme first: a network can advertise both
		// 'exact' and 'upto', so a network-only match could return the wrong
		// scheme and (for settle) drop the up-to override.
		for _, a := range accepts {
			if a.Network == acceptedNetwork && (acceptedScheme == "" || a.Scheme == acceptedScheme) {
				return &a
			}
		}
		for _, a := range accepts {
			if a.Network == acceptedNetwork {
				return &a
			}
		}
		if logger != nil {
			logger.Warnf("credential network %s not in accepts, using first accept", acceptedNetwork)
		}
		return &accepts[0]
	}

	// No `accepted` on the payload (raw/older credential formats): fall back
	// to the first EVM accept.
	for _, a := range accepts {
		if strings.HasPrefix(a.Network, "eip155") {
			return &a
		}
	}
	if logger != nil {
		logger.Warnf("no EVM accept found, using first accept")
	}
	return &accepts[0]
}

// extractNetworkFromAccountID splits a fully-qualified account id "network:address"
// and returns the network. Ported from @atxp/common extractNetworkFromAccountId.
func extractNetworkFromAccountID(accountID string) (string, error) {
	network, _, err := splitAccountID(accountID)
	return network, err
}

// extractAddressFromAccountID returns the address portion of "network:address".
// Ported from @atxp/common extractAddressFromAccountId.
func extractAddressFromAccountID(accountID string) (string, error) {
	_, address, err := splitAccountID(accountID)
	return address, err
}

func splitAccountID(accountID string) (network, address string, err error) {
	parts := strings.Split(accountID, ":")
	if len(parts) != 2 {
		return "", "", &InvalidAccountIDError{AccountID: accountID}
	}
	return parts[0], parts[1], nil
}

// InvalidAccountIDError is returned when an account id is not "network:address".
type InvalidAccountIDError struct{ AccountID string }

func (e *InvalidAccountIDError) Error() string {
	return "atxp server: invalid accountId format " + e.AccountID + " (expected network:address)"
}
