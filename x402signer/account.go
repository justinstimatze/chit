package x402signer

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	atxp "github.com/justinstimatze/chit"
)

// x402PaymentOption mirrors one entry of an x402 challenge's accepts[] array
// (server/protocol.go's X402PaymentOption on the merchant side). Defined
// independently here rather than importing server/: the wire shape is a
// stable, documented contract between the two halves of the module, not
// something worth coupling the client to the merchant package for.
type x402PaymentOption struct {
	Scheme            string         `json:"scheme"`
	Network           string         `json:"network"` // CAIP-2, e.g. "eip155:8453"
	Amount            string         `json:"amount"`  // atomic units (e.g. micro-USDC), NOT decimal
	PayTo             string         `json:"payTo"`
	Asset             string         `json:"asset"` // token contract address
	MaxTimeoutSeconds int            `json:"maxTimeoutSeconds,omitempty"`
	Extra             map[string]any `json:"extra,omitempty"` // exact scheme carries {name, version} for the EIP-712 domain
}

type x402PaymentRequirements struct {
	X402Version int                 `json:"x402Version"`
	Accepts     []x402PaymentOption `json:"accepts"`
}

// selectExactAccept picks the first "exact"-scheme, EVM (eip155:*) accept from
// a challenge, optionally restricted to a pinned CAIP-2 network. This account
// only speaks EIP-3009 "exact" — "upto"/Permit2 and any Solana accept are
// deliberately skipped (see package doc's Non-goals).
func selectExactAccept(reqs x402PaymentRequirements, pinnedNetwork string) (*x402PaymentOption, error) {
	var offered []string
	for i := range reqs.Accepts {
		a := &reqs.Accepts[i]
		offered = append(offered, a.Scheme+"/"+a.Network)
		if a.Scheme != "exact" {
			continue
		}
		if !strings.HasPrefix(a.Network, "eip155:") {
			continue
		}
		if pinnedNetwork != "" && a.Network != pinnedNetwork {
			continue
		}
		return a, nil
	}
	return nil, fmt.Errorf("x402signer: no exact/eip155 accept found among offered schemes/networks %v (pinned network %q)", offered, pinnedNetwork)
}

// X402SignerAccount pays x402 "exact"-scheme challenges by signing an
// EIP-3009 transferWithAuthorization message with a raw secp256k1 key. See
// the package doc comment for the full scope and boundary (no upto/Permit2,
// no Solana, no keystore/KMS, no gas/broadcast, no OAuth-401 support).
type X402SignerAccount struct {
	priv          *ecdsa.PrivateKey
	address       string // EIP-55 checksummed 0x address, derived once at construction
	pinnedNetwork string // CAIP-2 network, e.g. "eip155:8453"; "" accepts any eip155 network offered
}

// NewFromPrivateKeyHex parses a "0x"-prefixed or bare hex-encoded 32-byte
// secp256k1 private key. pinnedNetwork, if non-empty, restricts Authorize to
// accepts on exactly that CAIP-2 network (e.g. "eip155:8453"); empty accepts
// the first matching "exact"-scheme EVM accept regardless of chain.
//
// Key management is explicitly not this type's job: callers load the key from
// wherever they like (env var, file, secret manager) and hand this
// constructor the raw material. There is no keystore, no KMS integration, no
// rotation support — see the package doc's Non-goals.
func NewFromPrivateKeyHex(hexKey, pinnedNetwork string) (*X402SignerAccount, error) {
	hexKey = strings.TrimPrefix(hexKey, "0x")
	priv, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		return nil, fmt.Errorf("x402signer: parse private key: %w", err)
	}
	return &X402SignerAccount{
		priv:          priv,
		address:       crypto.PubkeyToAddress(priv.PublicKey).Hex(),
		pinnedNetwork: pinnedNetwork,
	}, nil
}

// NewFromPrivateKey is the byte-slice equivalent of NewFromPrivateKeyHex, for
// callers that already hold raw key material (e.g. read from a file) and
// don't want a hex round-trip.
func NewFromPrivateKey(key []byte, pinnedNetwork string) (*X402SignerAccount, error) {
	priv, err := crypto.ToECDSA(key)
	if err != nil {
		return nil, fmt.Errorf("x402signer: parse private key: %w", err)
	}
	return &X402SignerAccount{
		priv:          priv,
		address:       crypto.PubkeyToAddress(priv.PublicKey).Hex(),
		pinnedNetwork: pinnedNetwork,
	}, nil
}

// Address returns the EIP-55 checksummed 0x address derived from the key —
// exposed so callers can e.g. log which payer address is being used without
// touching the private key itself.
func (a *X402SignerAccount) Address() string { return a.address }

// AccountID satisfies atxp.Account. A self-custodial signer has no ATXP
// accounts-server identity; its "account" is just its address.
func (a *X402SignerAccount) AccountID(ctx context.Context) (string, error) {
	return a.address, nil
}

// SignChallenge satisfies atxp.Account but always errors: this account is
// self-custodial and has no relationship with any OAuth authorization
// server. It can only pay x402 challenges presented as a direct HTTP 402 or
// JSON-RPC payment error, not resources gated behind an OAuth 401 (see the
// package doc comment). Returning ("", nil) here would let oauth.go's
// authenticate() proceed with an empty Bearer JWT and fail confusingly (or
// worse, "succeed" against a misconfigured authorization server) — an
// explicit error fails loudly at the one call site that would otherwise mask
// this limitation.
func (a *X402SignerAccount) SignChallenge(ctx context.Context, codeChallenge string) (string, error) {
	return "", fmt.Errorf("x402signer: this account is self-custodial and cannot complete an OAuth handshake; it only pays bare x402 challenges (HTTP 402 or JSON-RPC payment error), not resources gated behind an OAuth 401")
}

// SpendPermission satisfies atxp.Account. Returning ("", nil) is explicitly
// sanctioned by the interface's own doc comment for account types that don't
// support it — harmless here since it only omits spend_permission_token from
// an authorization URL this account will never build (see SignChallenge).
func (a *X402SignerAccount) SpendPermission(ctx context.Context, resourceURL string) (string, error) {
	return "", nil
}

// Authorize satisfies atxp.Account: selects the exact/EVM accept from the
// challenge, signs an EIP-3009 transferWithAuthorization for it, and returns
// the credential as base64-std JSON.
func (a *X402SignerAccount) Authorize(ctx context.Context, p atxp.AuthorizeParams) (atxp.AuthorizeResult, error) {
	if len(p.PaymentRequirements) == 0 {
		return atxp.AuthorizeResult{}, fmt.Errorf("x402signer: challenge carries no x402 paymentRequirements; this account only speaks x402")
	}
	var reqs x402PaymentRequirements
	if err := json.Unmarshal(p.PaymentRequirements, &reqs); err != nil {
		return atxp.AuthorizeResult{}, fmt.Errorf("x402signer: decode x402 paymentRequirements: %w", err)
	}
	accept, err := selectExactAccept(reqs, a.pinnedNetwork)
	if err != nil {
		return atxp.AuthorizeResult{}, err
	}

	value, ok := new(big.Int).SetString(accept.Amount, 10)
	if !ok {
		return atxp.AuthorizeResult{}, fmt.Errorf("x402signer: accept amount %q is not a valid integer (atomic units)", accept.Amount)
	}
	name, _ := accept.Extra["name"].(string)
	version, _ := accept.Extra["version"].(string)
	if name == "" || version == "" {
		return atxp.AuthorizeResult{}, fmt.Errorf("x402signer: accept for %s is missing extra.name/extra.version (needed for the EIP-712 domain); refusing to guess a default", accept.Network)
	}
	chainID, err := caip2ChainID(accept.Network)
	if err != nil {
		return atxp.AuthorizeResult{}, err
	}

	nonce, err := randomNonce()
	if err != nil {
		return atxp.AuthorizeResult{}, err
	}
	maxTimeout := accept.MaxTimeoutSeconds
	if maxTimeout <= 0 {
		maxTimeout = 300
	}
	now := time.Now()
	auth := transferAuthorization{
		From:        a.address,
		To:          accept.PayTo,
		Value:       value,
		ValidAfter:  big.NewInt(now.Add(-60 * time.Second).Unix()), // small clock-skew buffer
		ValidBefore: big.NewInt(now.Add(time.Duration(maxTimeout) * time.Second).Unix()),
		Nonce:       nonce,
	}
	domain := eip712Domain{
		Name:              name,
		Version:           version,
		ChainID:           chainID,
		VerifyingContract: accept.Asset,
	}

	sig, err := signTransferWithAuthorization(a.priv, domain, auth)
	if err != nil {
		return atxp.AuthorizeResult{}, err
	}
	// Wire shape is the standard x402 v2 PaymentPayload: x402Version, payload
	// (scheme-specific signature data), and accepted (the FULL matching
	// PaymentRequirements, not just {network,scheme}, per coinbase/x402's
	// go/types/v2.go PaymentPayload struct).
	credential := map[string]any{
		"x402Version": reqs.X402Version,
		"accepted": map[string]any{
			"scheme":            accept.Scheme,
			"network":           accept.Network,
			"asset":             accept.Asset,
			"amount":            accept.Amount,
			"payTo":             accept.PayTo,
			"maxTimeoutSeconds": accept.MaxTimeoutSeconds,
			"extra":             accept.Extra,
		},
		"payload": map[string]any{
			"signature": "0x" + hex.EncodeToString(sig),
			"authorization": map[string]any{
				"from":        auth.From,
				"to":          auth.To,
				"value":       auth.Value.String(),
				"validAfter":  auth.ValidAfter.String(),
				"validBefore": auth.ValidBefore.String(),
				"nonce":       "0x" + hex.EncodeToString(auth.Nonce[:]),
			},
		},
	}
	buf, err := json.Marshal(credential)
	if err != nil {
		return atxp.AuthorizeResult{}, fmt.Errorf("x402signer: marshal credential: %w", err)
	}

	return atxp.AuthorizeResult{
		Protocol:   "x402",
		Credential: base64.StdEncoding.EncodeToString(buf),
	}, nil
}

// caip2ChainID extracts the numeric chain id from a CAIP-2 "eip155:<id>"
// network identifier.
func caip2ChainID(network string) (int64, error) {
	id, ok := strings.CutPrefix(network, "eip155:")
	if !ok {
		return 0, fmt.Errorf("x402signer: %q is not an eip155 CAIP-2 network", network)
	}
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("x402signer: parse chain id from %q: %w", network, err)
	}
	return n, nil
}
