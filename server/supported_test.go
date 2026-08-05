package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchUptoFacilitatorAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/x402/supported" {
			t.Errorf("path = %q, want /x402/supported", r.URL.Path)
		}
		_, _ = io.WriteString(w, `{"eip155:8453":"0x7720030000000000000000000000000000000000"}`)
	}))
	defer srv.Close()

	got := fetchUptoFacilitatorAddresses(context.Background(), srv.URL, srv.Client(), nopLogger{})
	if got["eip155:8453"] != "0x7720030000000000000000000000000000000000" {
		t.Errorf("got = %v", got)
	}
}

func TestFetchUptoFacilitatorAddressesCaches(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_, _ = io.WriteString(w, `{"eip155:8453":"0xabc"}`)
	}))
	defer srv.Close()

	fetchUptoFacilitatorAddresses(context.Background(), srv.URL, srv.Client(), nopLogger{})
	fetchUptoFacilitatorAddresses(context.Background(), srv.URL, srv.Client(), nopLogger{})
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (second call served from cache)", calls)
	}
}

func TestFetchUptoFacilitatorAddressesFailsGracefully(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	got := fetchUptoFacilitatorAddresses(context.Background(), srv.URL, srv.Client(), nopLogger{})
	if len(got) != 0 {
		t.Errorf("got = %v, want empty on non-2xx", got)
	}
}

func TestFetchMppSupportedRequiresAllTempoFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mpp/supported" {
			t.Errorf("path = %q, want /mpp/supported", r.URL.Path)
		}
		// Missing operator — must be dropped, not advertised half-populated.
		_, _ = io.WriteString(w, `{"tempo":{"authorizedSigner":"0xsig","escrowContract":"0xesc"}}`)
	}))
	defer srv.Close()

	got := fetchMppSupported(context.Background(), srv.URL, srv.Client(), nopLogger{})
	if got.Tempo != nil {
		t.Errorf("Tempo = %+v, want nil (incomplete fields)", got.Tempo)
	}
}

func TestFetchMppSupportedTempoAndSolana(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{
			"tempo": {"authorizedSigner":"0xsig","operator":"0xop","escrowContract":"0xesc","chainId":42},
			"solana": {"authorizedSigner":"solSigner"}
		}`)
	}))
	defer srv.Close()

	got := fetchMppSupported(context.Background(), srv.URL, srv.Client(), nopLogger{})
	if got.Tempo == nil || got.Tempo.ChainID != 42 || got.Tempo.EscrowContract != "0xesc" {
		t.Errorf("Tempo = %+v", got.Tempo)
	}
	if got.Solana == nil || got.Solana.AuthorizedSigner != "solSigner" {
		t.Errorf("Solana = %+v", got.Solana)
	}
}

func TestFetchMppSupportedEmptyOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	got := fetchMppSupported(context.Background(), srv.URL, srv.Client(), nopLogger{})
	if got.Tempo != nil || got.Solana != nil {
		t.Errorf("got = %+v, want zero result on failure", got)
	}
}
