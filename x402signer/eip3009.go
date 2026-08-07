// Package x402signer is a self-custodial x402 "exact"-scheme Account for
// chit's client. Unlike the hosted ATXPAccount (root package, zero on-chain
// crypto), this account pays an x402 challenge by signing an EIP-3009
// "transferWithAuthorization" message with a raw secp256k1 private key.
//
// It never touches an RPC node, never broadcasts a transaction, and never
// pays gas: it only produces a signature. A facilitator (chosen by the
// merchant, outside this account's control) submits it on-chain later.
//
// Scope, deliberately: EIP-3009 "exact" scheme only. NOT supported: the
// "upto"/Permit2 scheme, Solana, any keystore/KMS integration (the
// constructor takes raw key bytes/hex — bring your own key material), and
// gas/broadcast. See account.go's doc comment for why this account type
// cannot pay OAuth-401-gated resources (only bare-402 x402 challenges).
package x402signer

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// eip712Domain is the EIP-712 domain for a USDC-style EIP-3009 token contract.
type eip712Domain struct {
	Name              string
	Version           string
	ChainID           int64
	VerifyingContract string // 0x-prefixed token contract address
}

// transferAuthorization is the EIP-3009 transferWithAuthorization message.
type transferAuthorization struct {
	From        string   // 0x-prefixed payer address
	To          string   // 0x-prefixed payee address
	Value       *big.Int // atomic units (e.g. micro-USDC, 6 decimals)
	ValidAfter  *big.Int // unix seconds
	ValidBefore *big.Int // unix seconds
	Nonce       [32]byte // random, payer-chosen — anti-replay only, not derived from anything in the challenge
}

// randomNonce returns a fresh, cryptographically random EIP-3009 nonce.
func randomNonce() ([32]byte, error) {
	var n [32]byte
	if _, err := rand.Read(n[:]); err != nil {
		return n, fmt.Errorf("x402signer: generate nonce: %w", err)
	}
	return n, nil
}

// hashTransferWithAuthorization builds the EIP-712 typed data for an EIP-3009
// transferWithAuthorization message and returns its digest (ready to sign
// directly) plus the raw "\x19\x01"-prefixed preimage, mirroring
// apitypes.TypedDataAndHash's return shape.
func hashTransferWithAuthorization(domain eip712Domain, auth transferAuthorization) ([]byte, string, error) {
	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": {
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"TransferWithAuthorization": {
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"},
				{Name: "nonce", Type: "bytes32"},
			},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{
			Name:              domain.Name,
			Version:           domain.Version,
			ChainId:           math.NewHexOrDecimal256(domain.ChainID),
			VerifyingContract: domain.VerifyingContract,
		},
		Message: apitypes.TypedDataMessage{
			"from":        auth.From,
			"to":          auth.To,
			"value":       auth.Value,
			"validAfter":  auth.ValidAfter,
			"validBefore": auth.ValidBefore,
			"nonce":       auth.Nonce[:],
		},
	}
	return apitypes.TypedDataAndHash(typedData)
}

// signTransferWithAuthorization signs an EIP-3009 transferWithAuthorization
// message and returns the 65-byte recoverable ECDSA signature: r (32) || s
// (32) || v (1, 27 or 28) — the wire format Ethereum signature verifiers, and
// EIP-3009's transferWithAuthorization(...,v,r,s), expect.
func signTransferWithAuthorization(priv *ecdsa.PrivateKey, domain eip712Domain, auth transferAuthorization) ([]byte, error) {
	hash, _, err := hashTransferWithAuthorization(domain, auth)
	if err != nil {
		return nil, fmt.Errorf("x402signer: hash EIP-712 typed data: %w", err)
	}

	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		return nil, fmt.Errorf("x402signer: sign: %w", err)
	}
	// crypto.Sign returns the recovery id (last byte) as 0 or 1; Ethereum's
	// standard wire/on-chain convention — and EIP-3009's transferWithAuthorization
	// v parameter — is 27/28.
	sig[64] += 27
	return sig, nil
}
