package server

import (
	"encoding/base64"
	"encoding/json"
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
