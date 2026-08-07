package server

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestExtractX402PayerAddress(t *testing.T) {
	credential := map[string]any{
		"x402Version": 2,
		"accepted": map[string]any{
			"scheme": "exact", "network": "eip155:8453",
		},
		"payload": map[string]any{
			"signature": "0xdeadbeef",
			"authorization": map[string]any{
				"from": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
				"to":   "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
			},
		},
	}
	buf, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(buf)

	addr, err := ExtractX402PayerAddress(encoded)
	if err != nil {
		t.Fatalf("ExtractX402PayerAddress: %v", err)
	}
	if addr != "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" {
		t.Errorf("addr = %q, want the authorization's from address", addr)
	}
}

func TestExtractX402PayerAddressRejectsGarbage(t *testing.T) {
	if _, err := ExtractX402PayerAddress("not valid json or base64"); err == nil {
		t.Error("expected an error for unparseable credential")
	}
}

func TestExtractX402PayerAddressRejectsMissingPayload(t *testing.T) {
	// A credential with no "payload" field (e.g. the wrong scheme, or malformed).
	credential := map[string]any{"x402Version": 2, "accepted": map[string]any{"scheme": "exact"}}
	buf, _ := json.Marshal(credential)
	encoded := base64.StdEncoding.EncodeToString(buf)

	if _, err := ExtractX402PayerAddress(encoded); err == nil {
		t.Error("expected an error when the credential has no payload field")
	}
}
