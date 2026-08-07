package x402signer

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Known-answer test vector, computed independently with ethers.js v6
// (NOT this codebase, NOT go-ethereum) against a well-known, publicly
// documented test private key (Hardhat/Anvil default account #0 — not a
// secret, used across the whole Ethereum tooling ecosystem purely to produce
// a verifiable KAT). See the generating script's inputs reproduced below.
const (
	katPrivHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	katAddress = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	katTo      = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
	katSigHex  = "4f46f1af86b1f62019ab96fd7e546d8d7d20a264bb1794a74ca0803f125a55da70833846d6536d36cf32ba291b947af383c7f27634de9c8cbc9220cdbcb8b27b1b"
)

func katDomain() eip712Domain {
	return eip712Domain{
		Name:              "USD Coin",
		Version:           "2",
		ChainID:           8453,
		VerifyingContract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
	}
}

func katAuth(t *testing.T) transferAuthorization {
	t.Helper()
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = 0x11
	}
	return transferAuthorization{
		From:        katAddress,
		To:          katTo,
		Value:       big.NewInt(10000),
		ValidAfter:  big.NewInt(0),
		ValidBefore: big.NewInt(1780000000),
		Nonce:       nonce,
	}
}

func mustHexPriv(t *testing.T, hexKey string) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := crypto.HexToECDSA(hexKey)
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	return priv
}

func TestAddressDerivation(t *testing.T) {
	priv := mustHexPriv(t, katPrivHex)
	got := crypto.PubkeyToAddress(priv.PublicKey).Hex()
	if !strings.EqualFold(got, katAddress) {
		t.Errorf("address = %s, want %s", got, katAddress)
	}
}

func TestSignTransferWithAuthorization_KnownVector(t *testing.T) {
	priv := mustHexPriv(t, katPrivHex)
	sig, err := signTransferWithAuthorization(priv, katDomain(), katAuth(t))
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(sig)
	if got != katSigHex {
		t.Errorf("signature = %s\nwant       %s", got, katSigHex)
	}
	if len(sig) != 65 {
		t.Errorf("signature length = %d, want 65", len(sig))
	}
	if sig[64] != 27 && sig[64] != 28 {
		t.Errorf("v byte = %d, want 27 or 28", sig[64])
	}
}

// TestSignThenRecoverVerify is an internal-consistency check independent of
// the external KAT: sign, then recover the public key from the signature and
// the same digest apitypes.TypedDataAndHash would produce, and confirm it
// matches the signer's address. Catches recovery-id (v) bugs even without a
// golden vector, across several edge-case inputs.
func TestSignThenRecoverVerify(t *testing.T) {
	priv := mustHexPriv(t, katPrivHex)
	wantAddr := crypto.PubkeyToAddress(priv.PublicKey)

	cases := []transferAuthorization{
		katAuth(t),
		{ // validAfter=0, minimal value
			From: katAddress, To: katTo,
			Value: big.NewInt(1), ValidAfter: big.NewInt(0), ValidBefore: big.NewInt(1),
		},
		{ // large value, non-zero validAfter
			From: katAddress, To: katTo,
			Value:       new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), // 1e18, atomic-unit-scale edge case
			ValidAfter:  big.NewInt(1700000000),
			ValidBefore: big.NewInt(1800000000),
		},
	}

	for i, auth := range cases {
		sig, err := signTransferWithAuthorization(priv, katDomain(), auth)
		if err != nil {
			t.Fatalf("case %d: sign: %v", i, err)
		}
		hash, _, err := hashTransferWithAuthorization(katDomain(), auth)
		if err != nil {
			t.Fatalf("case %d: hash: %v", i, err)
		}
		// Ethereum's Sign/Ecrecover pair uses v in {0,1}; we stored v as {27,28}.
		recoverSig := append(append([]byte{}, sig[:64]...), sig[64]-27)
		pub, err := crypto.SigToPub(hash, recoverSig)
		if err != nil {
			t.Fatalf("case %d: SigToPub: %v", i, err)
		}
		gotAddr := crypto.PubkeyToAddress(*pub)
		if gotAddr != wantAddr {
			t.Errorf("case %d: recovered address = %s, want %s", i, gotAddr.Hex(), wantAddr.Hex())
		}
	}
}
