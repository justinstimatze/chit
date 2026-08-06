# ATXP Go client — build handoff

## STATUS (2026-06-10): client built + tested, ready for integration

A working hosted-account client lives in `internal/atxp/` — `account.go`, `oauth.go`,
`store.go`, `transport.go`, `client.go` (+ `atxp_test.go`, `live_test.go`). It builds,
vets, gofmt-clean. **9 unit tests pass** (httptest, incl. a full 401→OAuth→payment→200
flow). Use:

```go
c, _ := atxp.New(atxp.Config{ConnectionString: os.Getenv("ATXP_CONNECTION")})
sess, _ := c.Connect(ctx, "https://search.mcp.atxp.ai/")
res, _ := sess.CallTool(ctx, &mcp.CallToolParams{Name: "search", Arguments: map[string]any{"query": "..."}})
```

**Proven live against production** (`go test -tags atxplive`): PRM/AS discovery + dynamic
client registration (real `client_id` minted on `auth.atxp.ai`); `/me` (credential valid).
The client wiring uses go-sdk v1.6.1 `StreamableClientTransport.HTTPClient` — no MCP fork.

**FULLY proven live end-to-end (2026-06-10):** `TestLivePaidPath` passed against
production — discovery → DCR → `/me` → `/sign` → `/authorize/auto` → MCP payment retry →
a real `search_search` result, paid from a funded account. The `/sign` and payment-settle
paths (built from TS source) interlock correctly with the real servers. Nothing in the
client is unverified anymore.

**Account model gotcha (cost real time — flag for setup):**
- `npx atxp agent register` creates an **orphan** agent (`isOrphan: true`, no human login,
  no owner). A fresh orphan is `fraud_blocked` and cannot `/sign` or pay until a payment
  method is added to *that specific account*. My earlier "new accounts get ~10 free IOU
  credits" was wrong — registration showed `Funded: 0`.
- The web `/fund` page funds the account you're **logged into by email** (a separate
  `human`-type owner account), NOT the orphan agent. Funding the orphan must go through
  `npx atxp fund` (which bills the token in `~/.atxp/config`).
- What actually worked: a `human`-type account funded via the web, whose connection string
  is exposed on the dashboard **Servers** page. That account had `funded: true`, `/sign`
  returned `signed: true`, and the paid call succeeded. So gemot can use a funded account's
  dashboard connection string directly — it does not need the orphan `agent register` flow.
- The client surfaces the blocked state as a typed `RestrictionError`; `live_test.go`
  skips with that reason if the configured account is unfunded/blocked.

Re-run live: `ATXP_CONNECTION=<funded-account-connection-string> go test -tags atxplive -run TestLivePaidPath ./internal/atxp/...`
(or persist via `npx atxp login --token "..."`, which `live_test.go` reads from `~/.atxp/config`).

**Pull-mode `/charge` gotcha — needs an established Connection, not just funds:**
- An account's displayed balance (dashboard, `npx atxp balance`) is real and spendable, but
  only through a full OAuth-authorized session with a specific resource — what happens
  transparently when a client calls a first-party tool like `search`.
- `server.RequirePayment`'s on-demand path (`SourceAccountToken` → `POST /charge`) only
  succeeds if the payer has already connected to *that specific resource* — see
  **Connections → Add MCP Server** on `accounts.atxp.ai`. Without a Connection, `/charge`
  returns 402 with `shortage: <amount>` for any amount, regardless of real balance —
  `GET /balance` on the same auth server independently confirms this by returning `0` for
  an unconnected caller.
- A Connection forms automatically and headlessly the first time a client pays a resource
  (no dashboard step needed) — chit's client already does this. It requires the resource to
  be a real, reachable HTTPS server (PRM discovery + DCR + `/authorize` all hit it over the
  network); a placeholder/synthetic `Resource` string can never form one.

**Reference merchant + how to live-test a Connection forming for real:**
- `examples/paidmcp` is a real, runnable MCP server wrapping `server.Merchant` (a paid
  `ping` tool, `$0.01`) and `examples/paidmcp/client` drives the payer side through chit's
  client package — useful whenever you need an actual reachable resource to test against,
  not just `server/live_test.go`'s in-process challenge checks.
- To expose it publicly for a real OAuth handshake: `tailscale funnel <port>` (needs Funnel
  enabled on the tailnet and `sudo tailscale set --operator=$USER` once, run interactively —
  not through a non-TTY agent shell). Plain private Tailscale networking is NOT enough;
  ATXP's cloud backend needs a real public URL.
- `server.StaticDestination` needs real chain addresses in `Addresses` (from the merchant
  account's own `GET /me` → `sources[]`), not just the bare `ID` — otherwise x402/MPP
  options are silently empty (`no x402-compatible networks among N sources` in the log).

**Bug found and fixed this way (2026-08-05):** `store.go`'s `GetAccessToken` parent-path
walk had a trailing-slash mismatch — a token saved for a bare origin (`https://host`, what
`authenticate()` saves under when the resource URL has no path) never matched a lookup for
a single-segment request path (`https://host/mcp`), so the walk gave up one level short of
the origin. This silently forced a full re-authentication on every single request instead of
reusing the cached token. Invisible until now because the only resource ever live-tested
(`search.mcp.atxp.ai`) happens to serve at the root path, hiding the mismatch by coincidence.
Fixed in `store.go`; regression test `TestMemoryStoreParentPathWalkToBareOrigin` in
`atxp_test.go`.

**Current live wall (2026-08-05, not a chit issue):** with the above fixed, a Connection now
forms correctly and a real 402 challenge is issued — but the actual settlement call fails at
`auth.atxp.ai`'s `/authorize/auto` with `403 Destination not allowed for IOU conversion`.
Unaffected by enabling "Enable MCP servers" on the merchant account's Servers page, or by
attaching real chain addresses to the destination. Looks like a platform-side restriction on
which accounts can receive converted funds (possibly compliance-related) — not something
fixable via chit config. Worth asking ATXP support about directly with this exact error.

### Open decisions for the gemot session (architecture-dependent — not decided here)

- Where `ATXP_CONNECTION` lives in gemot config (env / config file / secret store). It is
  **wallet-grade**: never log it, never pass as a CLI arg, never send outbound. The CLI
  stores it in `~/.atxp/config`; `liveConnectionString()` in live_test.go shows the read.
- Which ATXP tools gemot calls and where in the deliberation flow (search? image? none?).
- Funding policy: one shared agent account vs per-user/per-deliberation; Stripe vs USDC.
- The call sites wiring `atxp.Client` into the deliberation engine.

---



Goal: let gemot (Go) call paid ATXP MCP tools (web search, image/video/music gen, X
search, SMS, voice, code exec, …) using a **hosted ATXP account** (connection string).
Inference stays on the native Anthropic SDK — ATXP is used only as a paid-tool rail.

Source of truth: read off the TypeScript SDK at `github.com/atxp-dev/sdk`
(packages `atxp-client`, `atxp-common`). Clone was at `/tmp/atxp-sdk`. All file:line
references below are into that tree.

## Scope decision

ATXP has **two account types** (`atxpFetcher.ts:238`):

- **`ATXPAccount` (hosted, connection string)** — `usesAccountsAuthorize = true`. The
  client does **zero on-chain crypto**: every signing/settlement op is an HTTP call to
  the ATXP accounts server. Only `ATXPAccountHandler` is used; the x402/MPP local payment
  makers are never instantiated. **This is what gemot builds.**
- Self-custodial (Base/Solana wallet) — uses `@x402/evm`, EIP-712 signing,
  `X402ProtocolHandler`/`MPPProtocolHandler`. **Partially built (2026-08-05):**
  `x402signer/` implements EIP-3009 "exact"-scheme signing on EVM chains as an
  `atxp.Account` — see its package doc comment for the full scope. Still out
  of scope: the `upto`/Permit2 x402 scheme, Solana, and MPP entirely.
  Rationale for building this despite the "hosted account only" default: the
  hosted/ATXP-native rail turns out to be restricted to ATXP's own first-party
  services for real settlement (see the pull-mode/IOU-conversion notes above)
  — x402 (and MPP) are the actual open, direct-settlement rails third-party
  payments go through.

Confirmed: **no Go (or Python-native) ATXP SDK exists.** `atxp-dev` is ~17 repos, all
TS/JS. The only native SDK is `@atxp/client` (npm). Python/other support is framework
adapters + raw HTTP.

## Connection string

A URL: `https://accounts.atxp.ai/?connection_token=<TOKEN>&account_id=<ID>`
(`account_id` optional; fetched from `/me` if absent). Parse → `origin`, `token`,
`accountId?` (`atxpAccount.ts:12`). Qualified account id is `atxp:<accountId>`.

## ATXP accounts-server endpoints (the hosted backend)

All on `origin`. Auth header differs per endpoint — match exactly:

| Endpoint | Method | Auth header | Body | Returns |
|---|---|---|---|---|
| `/me` | GET | `Bearer <token>` | — | `{accountId, …}` |
| `/sign` | POST | `Basic base64(token+":")` | `{paymentRequestId, codeChallenge, accountId?}` | `{jwt}` |
| `/authorize/auto` | POST | `Basic base64(token+":")` | see below | `{protocol, credential, context?}` |
| `/spend-permission` | POST | `Bearer <token>` | `{resourceUrl}` | `{spendPermissionToken}` |
| `/pay` | POST | `Basic base64(token+":")` | `{destinations[], memo, paymentRequestId?}` | `{transactionId, chain, currency, …}` |
| `/address_for_payment` | POST | `Basic base64(token+":")` | `{amount, currency, receiver, memo}` | `{sourceAddress, sourceNetwork?}` |
| `/account/{id}/sources` | GET | none (Accept only) | — | `Source[]` |

`Basic` = `"Basic " + base64(token + ":")` (blank password, `atxpAccount.ts:6`).

For the hosted MCP-tool path you only need **`/me`, `/sign`, `/authorize/auto`**
(and optionally `/spend-permission`). `/pay` and `/address_for_payment` are the
self-custodial push-mode path — not needed.

## Flow — calling an MCP tool (hosted account)

The whole client is a **fetch wrapper** around MCP's Streamable HTTP transport
(`atxpClient.ts:83`, `atxpFetcher.ts:845`). In Go, implement it as a custom
`http.RoundTripper` (or `*http.Client`) handed to the go-sdk Streamable HTTP transport.

### Leg 1 — OAuth handshake (first call to an MCP server → 401)

`oAuth.ts` + `oAuthResource.ts`.

1. MCP request → server returns **401** with `WWW-Authenticate: Bearer
   resource_metadata="<PRM URL>"` (also accept a bare-URL form) (`oAuth.ts:88`).
2. Discover the authorization server (`oAuthResource.ts:150`):
   - GET `<resourceUrl>/.well-known/oauth-protected-resource` (RFC 9728) →
     `authorization_servers[0]`.
   - Fallback if 404 (non-strict): GET
     `<resourceUrl-origin>/.well-known/oauth-authorization-server` → `issuer`.
   - Discovery request on the AS URL → AS metadata
     (`authorization_endpoint`, `token_endpoint`, `registration_endpoint`).
3. Client credentials for the AS issuer (`oAuthResource.ts:registerClient`): from DB,
   else **Dynamic Client Registration** (RFC 7591) POST to `registration_endpoint`
   with headers `X-ATXP-Registration-Type: client` (+ `X-ATXP-TOKEN: <token>` if set).
   Cache by issuer. (Concurrent-registration lock exists in TS; single-flight in Go.)
4. (Optional) POST `/spend-permission` (Bearer) → `spendPermissionToken`.
5. Build authorization URL (`oAuth.ts:makeAuthorizationUrl`): params `client_id`,
   `redirect_uri`, `response_type=code`, `code_challenge` (**S256**),
   `code_challenge_method=S256`, `state`, `resource=<resourceUrl>`,
   `spend_permission_token?`.
6. **ATXP twist** (`atxpFetcher.ts:527`, the `makeAuthRequestWithPaymentMaker`): instead
   of a browser redirect, GET `authorizationUrl + "&redirect=false"` with header
   `Authorization: Bearer <JWT>`, where the JWT comes from POST `/sign`
   `{paymentRequestId:"", codeChallenge:<the challenge>}`. Server replies either:
   - 3xx with `Location: <callback?code=…&state=…>`, or
   - 200 with body `{redirect: "<callback?code=…&state=…>"}` (the `redirect=false` hack).
7. Handle callback (`oAuth.ts:handleCallback`): parse `state` → look up saved PKCE →
   validate → **exchange code** at `token_endpoint` (auth-code grant + `code_verifier`)
   → `{access_token, refresh_token, expires_in}`. Save keyed by (userId=accountId, url).
8. Retry the MCP request with `Authorization: Bearer <access_token>`.

Token refresh (`oAuth.ts:fetch`): on 401 carrying `error="invalid_grant"`, refresh via
`refresh_token` grant, retry once.

### Leg 2 — payment challenge (tool call → payment required)

Trigger: HTTP **402**, or an MCP JSON-RPC **error code `-30402` or `-32042`** whose
`data` carries `chargeAmount`, `x402`, `mpp`, `paymentRequestUrl`, `paymentRequestId`
(`atxpFetcher.ts:471`, `:896`). For MCP the challenge arrives inside a 200 JSON-RPC body;
TS synthesizes a fake 402 Response to feed the handler (`atxpFetcher.ts:764`) — in Go just
branch on the parsed error directly.

Hosted path = `ATXPAccountHandler` only (`atxpAccountHandler.ts`):

1. Build authorize params from challenge data (`buildAuthorizeParams`): `amount`
   (`chargeAmount`), `destination`/`receiver`, `paymentRequirements` (from `x402.accepts`,
   non-`atxp` networks), `challenges` (from `mpp`). If destination still unknown, GET
   `paymentRequestUrl` and read `options[0]`.
2. POST `/authorize/auto` (Basic) — body:
   ```json
   {"protocols":["atxp"],            // +"x402" if paymentRequirements present, +"mpp" if challenges
    "amount":"<str>","receiver":"<dest>","memo":"<iss/payee>","currency":"USDC",
    "paymentRequirements":{...},     // optional
    "challenges":[...]}              // optional
   ```
   60s timeout. Response `{protocol, credential, context?}`. If `protocol==="atxp"`,
   parse the credential JSON and inject `sourceAccountToken = <token>` before re-stringify
   (`atxpAccount.ts:authorize`).
3. Map credential → header (`paymentHeaders.ts`):
   - `x402` → `X-PAYMENT: <credential>` (+ `Access-Control-Expose-Headers: X-PAYMENT-RESPONSE`)
   - `mpp`  → `Authorization: Payment <credential>` (do **not** also set Bearer)
   - `atxp` → `X-ATXP-PAYMENT: <credential>`
   - plus `X-ATXP-Payment-Request-Id: <id>` if present.
4. Retry the request **through the OAuth fetch** so the Bearer token is also attached
   (server wants both the payment header AND OAuth identity, `atxpFetcher.ts:737`).

## Go component map

| Concern | Go |
|---|---|
| MCP Streamable HTTP client | `github.com/modelcontextprotocol/go-sdk` — inject custom `*http.Client`/RoundTripper |
| OAuth token grants + PKCE | `golang.org/x/oauth2` (S256 PKCE); auth-code + refresh |
| PRM/AS discovery (RFC 9728/8414) + DCR (RFC 7591) | plain `net/http` — ~150 lines, no single lib |
| PKCE values | `crypto/rand`, `crypto/sha256`, `encoding/base64` RawURLEncoding |
| JWT for code_challenge | **none** — `/sign` returns it; just forward the string |
| On-chain signing | **none** for hosted path |
| Token/PKCE/cred store | small interface; in-memory map is fine (mirror `OAuthDb`) |

`OAuthDb` surface to mirror: `save/getPKCEValues(userId, state)`,
`save/getClientCredentials(issuer)`, `save/getAccessToken(userId, url)` — note token
lookup walks parent paths (`oAuthResource.ts:getAccessToken`).

## Build order (~3 focused days)

1. **~½d** — connection-string parse + accounts-server client (`/me`, `/sign`,
   `/authorize/auto`, `/spend-permission`). Pure JSON-over-HTTP.
2. **~1d** — OAuth: in-memory store, PRM/AS discovery, DCR, PKCE, code exchange + refresh.
   Meatiest piece.
3. **~1d** — the RoundTripper wrapper: 401→Leg 1 (incl. `/sign` + `redirect=false`),
   402/`-30402`/`-32042`→Leg 2 (`/authorize/auto`→header→retry).
4. **~½d** — wire into the go-sdk transport; integration-test against a live ATXP MCP
   server (start with search, cheapest).

## Verify against a live server before/while building

- Exact `WWW-Authenticate` format ATXP MCP servers actually return on 401.
- Whether they use the `redirect=false` 200-with-body trick or a real 3xx (handle both).
- go-sdk version's hook for a custom `*http.Client` on the Streamable HTTP transport.
- `x/oauth2` has **no** DCR — confirm and hand-roll it; confirm PKCE S256 helper version.
- Which protocol `/authorize/auto` returns for ATXP's own tool servers (likely `atxp`),
  so header mapping is exercised end-to-end.
