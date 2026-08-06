package atxp

import (
	"net/url"
	"strings"
	"sync"
)

// PKCEValues are the per-authorization values stashed between building the
// authorization URL and handling the callback, keyed by OAuth state.
type PKCEValues struct {
	URL           string // the resource URL the flow was started for (token key)
	CodeVerifier  string
	CodeChallenge string
	ResourceURL   string
}

// ClientCredentials are the dynamic-client-registration result for an
// authorization server, keyed by the server's issuer.
type ClientCredentials struct {
	ClientID     string
	ClientSecret string // empty for a public client
	RedirectURI  string
}

// AccessToken is a stored OAuth token for a (userID, resource) pair.
type AccessToken struct {
	ResourceURL  string
	AccessToken  string
	RefreshToken string
	ExpiresAt    int64 // unix seconds, 0 = unknown
}

// Store persists OAuth state. The in-memory implementation mirrors the TS
// MemoryOAuthDb closely enough for a single process; a deliberation server that
// wants tokens to survive restarts can supply a backing implementation.
//
// Token lookup walks parent paths so a token issued for a server root also
// satisfies requests to sub-paths (see GetAccessToken).
type Store interface {
	SavePKCE(userID, state string, v PKCEValues)
	GetPKCE(userID, state string) (PKCEValues, bool)

	SaveClientCredentials(issuer string, c ClientCredentials)
	GetClientCredentials(issuer string) (ClientCredentials, bool)

	SaveAccessToken(userID, url string, t AccessToken)
	GetAccessToken(userID, url string) (AccessToken, bool)
}

// MemoryStore is a process-local Store.
type MemoryStore struct {
	mu     sync.Mutex
	pkce   map[string]PKCEValues        // userID|state
	creds  map[string]ClientCredentials // issuer
	tokens map[string]AccessToken       // userID|trimmedURL
}

// NewMemoryStore returns an empty in-memory Store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		pkce:   map[string]PKCEValues{},
		creds:  map[string]ClientCredentials{},
		tokens: map[string]AccessToken{},
	}
}

func (s *MemoryStore) SavePKCE(userID, state string, v PKCEValues) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pkce[userID+"|"+state] = v
}

func (s *MemoryStore) GetPKCE(userID, state string) (PKCEValues, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.pkce[userID+"|"+state]
	return v, ok
}

func (s *MemoryStore) SaveClientCredentials(issuer string, c ClientCredentials) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creds[issuer] = c
}

func (s *MemoryStore) GetClientCredentials(issuer string) (ClientCredentials, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.creds[issuer]
	return c, ok
}

func (s *MemoryStore) SaveAccessToken(userID, u string, t AccessToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[userID+"|"+trimToPath(u)] = t
}

// GetAccessToken returns the token for the exact path, falling back to parent
// paths up to the origin — mirroring oAuthResource.ts getAccessToken.
func (s *MemoryStore) GetAccessToken(userID, u string) (AccessToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := trimToPath(u)
	for {
		if t, ok := s.tokens[userID+"|"+p]; ok {
			return t, true
		}
		parent := parentPath(p)
		if parent != "" {
			// parentPath may return an origin with a trailing "/" (path "/");
			// re-trim so it matches the no-trailing-slash form trimToPath saved
			// the origin-level key under, or the walk stops one level short of
			// the origin and a token saved for the bare origin never matches a
			// single-segment request path (e.g. saved "https://x.ai", looked up
			// "https://x.ai/mcp").
			parent = trimToPath(parent)
		}
		if parent == "" || parent == p {
			return AccessToken{}, false
		}
		p = parent
	}
}

// trimToPath reduces a URL to scheme://host/path (drops query and fragment) and
// canonicalizes by removing a trailing slash, so a token saved for an origin and
// a request to that origin with a trailing slash hash to the same key.
func trimToPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := strings.TrimRight(u.Path, "/")
	return u.Scheme + "://" + u.Host + p
}

// parentPath strips the last path segment, returning "" when at the root.
func parentPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	p := strings.TrimRight(u.Path, "/")
	idx := strings.LastIndex(p, "/")
	if idx <= 0 {
		// At or above the root path.
		if u.Path == "" || u.Path == "/" {
			return ""
		}
		u.Path = "/"
		res := u.Scheme + "://" + u.Host + u.Path
		if res == raw {
			return ""
		}
		return res
	}
	u.Path = p[:idx]
	res := u.Scheme + "://" + u.Host + u.Path
	if res == raw {
		return ""
	}
	return res
}
