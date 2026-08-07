package atxp

import (
	"context"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Config configures an ATXP client.
type Config struct {
	// ConnectionString is the hosted-account credential, e.g.
	// "https://accounts.atxp.ai/?connection_token=...&account_id=...".
	ConnectionString string
	// HTTPClient is used for accounts-server and OAuth calls. Optional.
	HTTPClient *http.Client
	// Store persists OAuth tokens/credentials. Defaults to an in-memory store.
	Store Store
	// CallbackURL is the OAuth redirect_uri registered with the auth server.
	// It is never actually navigated (ATXP returns the code directly), so the
	// default placeholder is fine.
	CallbackURL string
}

// Client connects to ATXP MCP tool servers, transparently handling OAuth and
// per-call payments. account is the Account interface, not the concrete
// hosted ATXPAccount, so NewWithAccount can hand in a different backend (e.g.
// a self-custodial x402 signer) while reusing this same transport/OAuth glue.
type Client struct {
	account Account
	store   Store
	httpc   *http.Client
	cbURL   string
}

// New builds a Client backed by a hosted ATXPAccount from a connection string.
func New(cfg Config) (*Client, error) {
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 65 * time.Second}
	}
	acct, err := NewATXPAccount(cfg.ConnectionString, hc)
	if err != nil {
		return nil, err
	}
	return newClientWithAccount(cfg, acct, hc)
}

// NewWithAccount builds a Client backed by any Account implementation (e.g. a
// self-custodial signer from a subpackage like x402signer) instead of the
// hosted ATXPAccount. cfg.ConnectionString is ignored; the other Config
// fields (HTTPClient, Store, CallbackURL) still apply.
func NewWithAccount(cfg Config, account Account) (*Client, error) {
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 65 * time.Second}
	}
	return newClientWithAccount(cfg, account, hc)
}

func newClientWithAccount(cfg Config, account Account, hc *http.Client) (*Client, error) {
	store := cfg.Store
	if store == nil {
		store = NewMemoryStore()
	}
	cb := cfg.CallbackURL
	if cb == "" {
		cb = "http://localhost:3000/unused-dummy-atxp-callback"
	}
	return &Client{account: account, store: store, httpc: hc, cbURL: cb}, nil
}

// HTTPClient returns an *http.Client whose transport performs the ATXP OAuth +
// payment handshake. It can be handed to any HTTP-based MCP transport, or used
// directly against ATXP REST endpoints.
func (c *Client) HTTPClient() *http.Client {
	base := c.httpc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	rt := &roundTripper{
		base:    base,
		account: c.account,
		store:   c.store,
		oauth: &oauthClient{
			account:     c.account,
			store:       c.store,
			http:        c.httpc,
			callbackURL: c.cbURL,
		},
	}
	return &http.Client{Transport: rt, Timeout: c.httpc.Timeout}
}

// Connect opens an MCP session to the given ATXP tool server (e.g.
// "https://search.mcp.atxp.ai/"). Payments and auth are handled transparently
// on each tool call. The caller owns the returned session and must Close it.
func (c *Client) Connect(ctx context.Context, serverURL string) (*mcp.ClientSession, error) {
	transport := &mcp.StreamableClientTransport{
		Endpoint:   serverURL,
		HTTPClient: c.HTTPClient(),
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "chit", Version: "0.1.0"}, nil)
	return client.Connect(ctx, transport, nil)
}
