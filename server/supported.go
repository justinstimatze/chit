package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Fetches for the authorization server's protocol "supported" endpoints —
// GET /x402/supported (upto facilitator addresses) and GET /mpp/supported
// (Tempo/Solana MPP session params). Ported from omniChallenge.ts
// fetchUptoFacilitatorAddresses / fetchMppSupported.
//
// Both are best-effort: a failure logs a warning and returns an empty/nil
// result so the omni-challenge simply omits the metered variant (upto accept,
// session-intent MPP challenge) rather than failing the whole challenge.

// supportedCacheTTL bounds how long a fetched result is reused. The
// facilitator/settler address can rotate; a long-lived merchant process must
// not advertise a stale one indefinitely.
const supportedCacheTTL = 10 * time.Minute

// ttlCache is a small per-key cache with a bounded TTL. It does not dedupe
// concurrent fetches for the same key (unlike the TS reference, which caches
// the pending promise) — a cache miss may briefly cause more than one
// identical GET, which is harmless for these idempotent, side-effect-free
// endpoints.
type ttlCache[T any] struct {
	ttl time.Duration

	mu    sync.Mutex
	at    map[string]time.Time
	value map[string]T
}

func newTTLCache[T any](ttl time.Duration) *ttlCache[T] {
	return &ttlCache[T]{ttl: ttl, at: map[string]time.Time{}, value: map[string]T{}}
}

func (c *ttlCache[T]) get(key string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.at[key]
	if !ok || time.Since(at) >= c.ttl {
		var zero T
		return zero, false
	}
	return c.value[key], true
}

func (c *ttlCache[T]) set(key string, v T) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at[key] = time.Now()
	c.value[key] = v
}

var facilitatorAddressCache = newTTLCache[map[string]string](supportedCacheTTL)

// fetchUptoFacilitatorAddresses fetches the CAIP-2-network → upto-facilitator-
// address map from the authorization server's GET /x402/supported. On any
// failure it logs a warning and returns nil (the x402 challenge then
// advertises `exact` only). The empty/failed result is not cached, so a later
// call can retry once the facilitator is reachable again. Ported from
// omniChallenge.ts fetchUptoFacilitatorAddresses.
func fetchUptoFacilitatorAddresses(ctx context.Context, authServer string, hc *http.Client, logger Logger) map[string]string {
	endpoint, err := url.JoinPath(authServer, "/x402/supported")
	if err != nil {
		logger.Warnf("fetchUptoFacilitatorAddresses: build url: %v; advertising exact only", err)
		return nil
	}
	if v, ok := facilitatorAddressCache.get(endpoint); ok {
		return v
	}

	result := getJSONMap(ctx, endpoint, hc, logger, "fetchUptoFacilitatorAddresses")
	if len(result) > 0 {
		facilitatorAddressCache.set(endpoint, result)
	}
	return result
}

func getJSONMap(ctx context.Context, endpoint string, hc *http.Client, logger Logger, caller string) map[string]string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		logger.Warnf("%s: build request for %s: %v; advertising exact only", caller, endpoint, err)
		return nil
	}
	resp, err := hc.Do(req)
	if err != nil {
		logger.Warnf("%s: failed to fetch %s: %v; advertising exact only", caller, endpoint, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warnf("%s: %s returned %d; advertising exact only", caller, endpoint, resp.StatusCode)
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		logger.Warnf("%s: read %s: %v; advertising exact only", caller, endpoint, err)
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal(body, &out); err != nil {
		logger.Warnf("%s: decode %s: %v; advertising exact only", caller, endpoint, err)
		return nil
	}
	return out
}

// MppSessionSupport is the Tempo MPP session (TIP-1034) params advertised by
// the authorization server's GET /mpp/supported: the channel's authorized
// signer + operator (auth's settler key), the escrow precompile, and the
// chain id. Ported from omniChallenge.ts MppSessionSupport.
type MppSessionSupport struct {
	EscrowContract   string `json:"escrowContract"`
	AuthorizedSigner string `json:"authorizedSigner"`
	Operator         string `json:"operator"`
	ChainID          int    `json:"chainId"`
}

// SolanaMppSessionSupport is the Solana MPP session-channel params advertised
// by GET /mpp/supported. accounts opens the channel and uses its own
// operator/fee-payer, so the SDK only needs auth's Solana authorizedSigner.
// Ported from omniChallenge.ts SolanaMppSessionSupport.
type SolanaMppSessionSupport struct {
	AuthorizedSigner string `json:"authorizedSigner"`
}

var mppSupportedCache = newTTLCache[mppSupportedResult](supportedCacheTTL)

type mppSupportedResult struct {
	Tempo  *MppSessionSupport
	Solana *SolanaMppSessionSupport
}

func (r mppSupportedResult) empty() bool { return r.Tempo == nil && r.Solana == nil }

// fetchMppSupported fetches Tempo/Solana MPP session support from the
// authorization server's GET /mpp/supported. Response shape:
// `{"tempo": {...}|null, "solana": {...}|null}`. A chain's data is discarded
// unless every field required to open a channel is present. On any failure,
// or when auth advertises neither chain, returns a zero result (both nil) and
// the omni-challenge advertises `charge` only for MPP. Ported from
// omniChallenge.ts fetchMppSupported.
func fetchMppSupported(ctx context.Context, authServer string, hc *http.Client, logger Logger) mppSupportedResult {
	endpoint, err := url.JoinPath(authServer, "/mpp/supported")
	if err != nil {
		logger.Warnf("fetchMppSupported: build url: %v; advertising charge only", err)
		return mppSupportedResult{}
	}
	if v, ok := mppSupportedCache.get(endpoint); ok {
		return v
	}

	result := doFetchMppSupported(ctx, endpoint, hc, logger)
	if !result.empty() {
		mppSupportedCache.set(endpoint, result)
	}
	return result
}

func doFetchMppSupported(ctx context.Context, endpoint string, hc *http.Client, logger Logger) mppSupportedResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		logger.Warnf("fetchMppSupported: build request for %s: %v; advertising charge only", endpoint, err)
		return mppSupportedResult{}
	}
	resp, err := hc.Do(req)
	if err != nil {
		logger.Warnf("fetchMppSupported: failed to fetch %s: %v; advertising charge only", endpoint, err)
		return mppSupportedResult{}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Warnf("fetchMppSupported: %s returned %d; advertising charge only", endpoint, resp.StatusCode)
		return mppSupportedResult{}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		logger.Warnf("fetchMppSupported: read %s: %v; advertising charge only", endpoint, err)
		return mppSupportedResult{}
	}
	var raw struct {
		Tempo  *MppSessionSupport       `json:"tempo"`
		Solana *SolanaMppSessionSupport `json:"solana"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		logger.Warnf("fetchMppSupported: decode %s: %v; advertising charge only", endpoint, err)
		return mppSupportedResult{}
	}

	var out mppSupportedResult
	if t := raw.Tempo; t != nil && t.AuthorizedSigner != "" && t.Operator != "" && t.EscrowContract != "" {
		out.Tempo = t
	}
	if s := raw.Solana; s != nil && s.AuthorizedSigner != "" {
		out.Solana = s
	}
	return out
}
