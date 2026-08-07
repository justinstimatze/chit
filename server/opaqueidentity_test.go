package server

import "testing"

func fixedSigner(t *testing.T) *opaqueSigner {
	t.Helper()
	// Deterministic 32-byte key so tests don't depend on randomness.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	s, err := newOpaqueSigner(key)
	if err != nil {
		t.Fatalf("newOpaqueSigner: %v", err)
	}
	return s
}

func TestOpaqueRoundTrip(t *testing.T) {
	s := fixedSigner(t)
	id := s.sign("atxp:user-123", "pay-abc")
	if id.Sub != "atxp:user-123" {
		t.Errorf("sub = %q", id.Sub)
	}
	opaque := map[string]any{"atxp_sub": id.Sub, "sig": id.Sig}
	got, ok := s.verify(opaque, "pay-abc")
	if !ok || got != "atxp:user-123" {
		t.Fatalf("verify = (%q,%v), want (atxp:user-123,true)", got, ok)
	}
}

func TestOpaqueRejectsTamperedSub(t *testing.T) {
	s := fixedSigner(t)
	id := s.sign("atxp:user-123", "pay-abc")
	// Attacker swaps the sub but keeps the original signature.
	opaque := map[string]any{"atxp_sub": "atxp:attacker", "sig": id.Sig}
	if _, ok := s.verify(opaque, "pay-abc"); ok {
		t.Fatal("verify accepted a tampered sub")
	}
}

func TestOpaqueRejectsCrossChallengeReplay(t *testing.T) {
	s := fixedSigner(t)
	id := s.sign("atxp:user-123", "pay-abc")
	// Valid signature, but presented against a different challenge id.
	opaque := map[string]any{"atxp_sub": id.Sub, "sig": id.Sig}
	if _, ok := s.verify(opaque, "pay-DIFFERENT"); ok {
		t.Fatal("verify accepted a signature replayed across challenges")
	}
}

func TestOpaqueRejectsMalformed(t *testing.T) {
	s := fixedSigner(t)
	cases := []map[string]any{
		nil,
		{},
		{"atxp_sub": "x"},                      // missing sig
		{"sig": "deadbeef"},                    // missing sub
		{"atxp_sub": "x", "sig": "not-hex-zz"}, // non-hex signature
		{"atxp_sub": 42, "sig": "deadbeef"},    // wrong type
		{"atxp_sub": "x", "sig": ""},           // empty sig
	}
	for i, c := range cases {
		if _, ok := s.verify(c, "pay-abc"); ok {
			t.Errorf("case %d: verify accepted malformed opaque %v", i, c)
		}
	}
}

func TestOpaqueDifferentKeysDoNotVerify(t *testing.T) {
	s1 := fixedSigner(t)
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(255 - i)
	}
	s2, _ := newOpaqueSigner(key2)
	id := s1.sign("atxp:user", "pay-1")
	opaque := map[string]any{"atxp_sub": id.Sub, "sig": id.Sig}
	if _, ok := s2.verify(opaque, "pay-1"); ok {
		t.Fatal("a signature should not verify under a different key")
	}
}

func TestLoadOpaqueKeyRejectsBadEnv(t *testing.T) {
	t.Setenv("ATXP_OPAQUE_KEY", "not valid base64!!!")
	if _, err := loadOpaqueKey(); err == nil {
		t.Fatal("loadOpaqueKey accepted invalid base64")
	}
	t.Setenv("ATXP_OPAQUE_KEY", "QUJD") // base64 "ABC" — only 3 bytes
	if _, err := loadOpaqueKey(); err == nil {
		t.Fatal("loadOpaqueKey accepted a too-short key")
	}
}
