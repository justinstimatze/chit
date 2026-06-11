package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

// Opaque identity — a signed user identity embedded in the `opaque` field of an
// MPP challenge. Ported from opaqueIdentity.ts.
//
// Why it exists: on the payment retry the client sends `Authorization: Payment
// <credential>`, which displaces the `Authorization: Bearer <token>` that
// carried the caller's OAuth identity. Only one Authorization header can exist,
// so the identity is smuggled through the challenge's `opaque` field instead.
// The merchant signs {sub, challengeId} on the way out and recovers + verifies
// it on the way back.
//
// Security model (from the TS source, preserved here):
//   - The HMAC key never leaves the process.
//   - The signature binds the identity to a specific challenge ID, so an opaque
//     blob cannot be replayed against a different challenge.
//   - Challenges are short-lived (~5 min), so a random per-process key that
//     rotates on restart is acceptable for single-instance deployments. Set
//     ATXP_OPAQUE_KEY (base64) to share a key across instances behind a balancer.

// opaqueSigner signs and verifies opaque identities with a fixed HMAC-SHA256 key.
type opaqueSigner struct {
	key []byte
}

// newOpaqueSigner builds a signer. If key is non-nil it is used as-is (callers
// pass the decoded ATXP_OPAQUE_KEY). Otherwise loadOpaqueKey is consulted:
// ATXP_OPAQUE_KEY from the environment, or a fresh random 32-byte key.
func newOpaqueSigner(key []byte) (*opaqueSigner, error) {
	if len(key) == 0 {
		var err error
		key, err = loadOpaqueKey()
		if err != nil {
			return nil, err
		}
	}
	return &opaqueSigner{key: key}, nil
}

// loadOpaqueKey returns the key from ATXP_OPAQUE_KEY (base64-decoded) or, if that
// is unset, a cryptographically-random 32-byte key. A failure to read randomness
// is fatal to the caller — we never fall back to a weak or empty key.
func loadOpaqueKey() ([]byte, error) {
	if env := os.Getenv("ATXP_OPAQUE_KEY"); env != "" {
		key, err := base64.StdEncoding.DecodeString(env)
		if err != nil {
			return nil, fmt.Errorf("opaque: ATXP_OPAQUE_KEY is not valid base64: %w", err)
		}
		if len(key) < 16 {
			return nil, fmt.Errorf("opaque: ATXP_OPAQUE_KEY must decode to at least 16 bytes, got %d", len(key))
		}
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("opaque: generate random key: %w", err)
	}
	return key, nil
}

// opaqueIdentity is the {atxp_sub, sig} object placed in an MPP challenge's
// `opaque` field. JSON tags match the TS wire shape exactly.
type opaqueIdentity struct {
	Sub string `json:"atxp_sub"`
	Sig string `json:"sig"`
}

// macHex computes the lowercase-hex HMAC-SHA256 of "sub:challengeId". This is
// the exact preimage and encoding the TS SDK uses, so signatures are
// interoperable with a TS peer sharing the same key.
func (s *opaqueSigner) macHex(sub, challengeID string) string {
	mac := hmac.New(sha256.New, s.key)
	// hmac.Hash.Write never returns an error.
	mac.Write([]byte(sub + ":" + challengeID))
	return hex.EncodeToString(mac.Sum(nil))
}

// sign produces the opaque identity for embedding in a challenge.
func (s *opaqueSigner) sign(sub, challengeID string) opaqueIdentity {
	return opaqueIdentity{Sub: sub, Sig: s.macHex(sub, challengeID)}
}

// verify recovers the user sub from an opaque object echoed back on a retry,
// returning ("", false) unless the HMAC matches for this exact challenge ID.
//
// The comparison uses hmac.Equal (constant-time) on the raw MAC bytes. We decode
// the presented hex first so a malformed signature is rejected cleanly rather
// than mismatching on length.
func (s *opaqueSigner) verify(opaque map[string]any, challengeID string) (string, bool) {
	if opaque == nil {
		return "", false
	}
	sub, ok := opaque["atxp_sub"].(string)
	if !ok || sub == "" {
		return "", false
	}
	sigHex, ok := opaque["sig"].(string)
	if !ok || sigHex == "" {
		return "", false
	}
	presented, err := hex.DecodeString(sigHex)
	if err != nil {
		return "", false
	}
	expected, err := hex.DecodeString(s.macHex(sub, challengeID))
	if err != nil {
		return "", false
	}
	if !hmac.Equal(presented, expected) {
		return "", false
	}
	return sub, true
}
