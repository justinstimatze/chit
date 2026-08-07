// Package server is the merchant/server side of chit — the half that charges
// callers over ATXP. It is a clean-room Go port of the MIT-licensed
// @atxp/server TypeScript SDK (© Circuit and Chisel); chit is unofficial and
// not affiliated with or endorsed by them.
//
// Like the client, the merchant side does no on-chain crypto: settlement is
// delegated to the ATXP authorization server over HTTP. The only local crypto is
// the HMAC that signs the opaque identity carried through an MPP retry.
//
// The flow a merchant wires up:
//
//   - CheckToken authenticates the caller's OAuth bearer token (RFC 7662
//     introspection) and yields its subject.
//   - RequirePayment gates a metered operation: it attempts an on-demand charge
//     and, failing that, returns a Challenge to emit as an MCP/JSON-RPC payment
//     error. A nil Challenge with a nil error means the caller has paid.
//   - On a push-payment retry, Verify/Settle finalize the presented credential,
//     and RecoverOpaqueIdentity re-derives the caller identity that the bearer
//     token can no longer carry.
//
// Connection tokens and bearer tokens are wallet-grade secrets: chit never logs
// them, and the default Logger discards everything.
package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	atxp "github.com/justinstimatze/chit"
)

// Config configures a Merchant. Destination is the only required field.
type Config struct {
	// Destination is where payments are received. Required.
	Destination Destination

	// ConnectionToken is the merchant's own ATXP connection token. It is sent
	// (over HTTPS only) as the X-ATXP-TOKEN header during dynamic client
	// registration so the registered client is bound to the merchant's ATXP
	// account. Wallet-grade secret — never logged or echoed. Optional only if
	// the authorization server permits unauthenticated registration.
	ConnectionToken string

	// AuthServer is the ATXP authorization server base URL. Defaults to
	// https://auth.atxp.ai.
	AuthServer string

	// PayeeName labels the merchant in challenges and metadata, and doubles as
	// the dynamic-client-registration client_name sent to the authorization
	// server. Defaults to "An ATXP Server" — set this to something distinctive
	// in production. The auth server treats client_name as claimed once
	// registered; with the default Store (in-memory, lost on restart) a second
	// process registering under the same unset-default name, whether a
	// restart of this merchant or an unrelated one reusing the same
	// ConnectionToken, gets a permanent 409 for that name, with no way to
	// recover the original client_secret. See Store's doc comment.
	PayeeName string

	// Currency is the settlement currency. Defaults to "USDC".
	Currency string

	// MinimumPayment is a price floor applied to every charge. Must be <= $1.00.
	// The zero Amount means no floor.
	MinimumPayment Amount

	// AppName is an observability label (1–64 chars of [a-zA-Z0-9._-]) sent on
	// settle/verify calls. Untrusted by auth; do not use for billing.
	AppName string

	// ExpectedAudience, when set, is required to appear in an introspected
	// token's `aud`. Leaving it empty disables the audience check (the TS
	// default), but setting it to this resource's URL is strongly recommended.
	ExpectedAudience string

	// Store persists DCR client credentials (keyed by AS issuer). Defaults to a
	// process-local in-memory store, which loses its client_secret on every
	// restart. The authorization server does not let a new registration
	// reclaim an already-claimed client_name, so a restarted (or
	// ConnectionToken-sharing) merchant that doesn't set a distinctive
	// PayeeName will permanently fail dynamic client registration with a 409.
	// Production deployments should supply a persistent Store implementation.
	Store atxp.Store

	// HTTPClient is used for all authorization-server calls. Optional.
	HTTPClient *http.Client

	// Logger receives operational messages. Never receives secrets. Defaults to
	// a no-op logger.
	Logger Logger

	// OpaqueKey is the HMAC key for opaque-identity signing. When nil, the key
	// is loaded from ATXP_OPAQUE_KEY (base64) or randomly generated per process.
	OpaqueKey []byte

	// AllowHTTP permits plaintext HTTP to the authorization server. For local
	// development and tests ONLY — it disables the HTTPS requirement that keeps
	// the connection token from traversing the network in the clear.
	AllowHTTP bool
}

// Merchant charges callers over ATXP. Construct one with New and reuse it; it is
// safe for concurrent use.
type Merchant struct {
	destination      Destination
	authServer       string
	payeeName        string
	currency         string
	minimum          Amount
	appName          string
	expectedAudience string
	allowHTTP        bool

	resource      *resourceClient
	paymentServer PaymentServer
	opaque        *opaqueSigner
	httpc         *http.Client
	logger        Logger
	now           func() time.Time

	mu            sync.Mutex
	cachedDestID  string
	settlementVal *ProtocolSettlement
}

// New builds a Merchant from a Config.
func New(cfg Config) (*Merchant, error) {
	if cfg.Destination == nil {
		return nil, fmt.Errorf("atxp server: Destination is required")
	}
	if cfg.MinimumPayment.GreaterThan(AmountFromMicros(1_000_000)) {
		return nil, fmt.Errorf("atxp server: MinimumPayment cannot exceed $1.00")
	}

	authServer := cfg.AuthServer
	if authServer == "" {
		authServer = defaultAuthorizationServer
	}
	payeeName := cfg.PayeeName
	if payeeName == "" {
		payeeName = "An ATXP Server"
	}
	currency := cfg.Currency
	if currency == "" {
		currency = "USDC"
	}
	store := cfg.Store
	if store == nil {
		store = atxp.NewMemoryStore()
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 65 * time.Second}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = nopLogger{}
	}
	opaque, err := newOpaqueSigner(cfg.OpaqueKey)
	if err != nil {
		return nil, err
	}

	resource := newResourceClient(store, hc, cfg.ConnectionToken, payeeName, cfg.AllowHTTP, logger)
	paymentServer := newPaymentServer(authServer, hc, resource, logger)

	return &Merchant{
		destination:      cfg.Destination,
		authServer:       authServer,
		payeeName:        payeeName,
		currency:         currency,
		minimum:          cfg.MinimumPayment,
		appName:          cfg.AppName,
		expectedAudience: cfg.ExpectedAudience,
		allowHTTP:        cfg.AllowHTTP,
		resource:         resource,
		paymentServer:    paymentServer,
		opaque:           opaque,
		httpc:            hc,
		logger:           logger,
		now:              time.Now,
	}, nil
}

// CheckToken authenticates a caller's Authorization header against the
// authorization server. resourceURL is this resource's URL (used to build the
// WWW-Authenticate metadata pointer and, when ExpectedAudience is set, to bound
// the audience). A passing TokenCheck carries the caller's identity in Data.Sub.
func (m *Merchant) CheckToken(ctx context.Context, resourceURL *url.URL, authHeader string) TokenCheck {
	return checkTokenCore(ctx, m.resource, m.authServer, resourceURL, authHeader, m.expectedAudience, m.now())
}

// CheckRequest is CheckToken applied to an *http.Request, deriving the resource
// URL from the request.
func (m *Merchant) CheckRequest(r *http.Request) TokenCheck {
	resourceURL := &url.URL{Scheme: schemeOf(r), Host: r.Host, Path: r.URL.Path}
	return m.CheckToken(r.Context(), resourceURL, r.Header.Get("Authorization"))
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

// ProtectedResourceMetadata builds the RFC 9728 document for a resource URL.
func (m *Merchant) ProtectedResourceMetadata(resource string) ProtectedResourceMetadata {
	name := m.payeeName
	if name == "" {
		name = resource
	}
	return ProtectedResourceMetadata{
		Resource:               resource,
		ResourceName:           name,
		AuthorizationServers:   []string{m.authServer},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        []string{"read", "write"},
	}
}

// RecoverOpaqueIdentity verifies the opaque identity echoed back in an MPP retry
// and returns the caller's subject. The caller extracts the opaque object from
// the presented credential and supplies the challenge id it was bound to.
// Returns ("", false) on any mismatch — fail closed.
func (m *Merchant) RecoverOpaqueIdentity(opaque map[string]any, challengeID string) (string, bool) {
	return m.opaque.verify(opaque, challengeID)
}

// destinationAccountID resolves and caches the merchant's own account id.
func (m *Merchant) destinationAccountID(ctx context.Context) (string, error) {
	m.mu.Lock()
	if m.cachedDestID != "" {
		id := m.cachedDestID
		m.mu.Unlock()
		return id, nil
	}
	m.mu.Unlock()

	id, err := m.destination.AccountID(ctx)
	if err != nil {
		return "", fmt.Errorf("atxp server: resolve destination account id: %w", err)
	}
	if id == "" {
		return "", fmt.Errorf("atxp server: destination returned an empty account id")
	}
	m.mu.Lock()
	m.cachedDestID = id
	m.mu.Unlock()
	return id, nil
}

// Settlement returns a ProtocolSettlement bound to the merchant's destination
// account, for finalizing push-payment credentials on a retry.
func (m *Merchant) Settlement(ctx context.Context) (*ProtocolSettlement, error) {
	m.mu.Lock()
	if m.settlementVal != nil {
		s := m.settlementVal
		m.mu.Unlock()
		return s, nil
	}
	m.mu.Unlock()

	destID, err := m.destinationAccountID(ctx)
	if err != nil {
		return nil, err
	}
	s := newProtocolSettlement(m.authServer, m.httpc, destID, m.appName, m.logger)
	m.mu.Lock()
	m.settlementVal = s
	m.mu.Unlock()
	return s, nil
}
