# chit — working notes for Claude Code

`chit` is an **unofficial Go module for ATXP** (Agent Transaction Protocol, by
Circuit & Chisel). It's a clean-room-from-source port of their MIT-licensed TypeScript
SDK (`github.com/atxp-dev/sdk`). Module path is the codename `github.com/justinstimatze/chit`;
the root package is `atxp` so callers write `atxp.New(...)`.

## Positioning constraints (do not violate)

- **Blatantly unofficial.** Never describe chit as "the official Go SDK" or imply
  endorsement. Descriptive use of the name "ATXP" only. The README and LICENSE carry
  the unofficial disclaimer and retain Circuit & Chisel's MIT copyright — keep both.
- **Connection strings are wallet-grade secrets.** Never log, echo, commit, pass as a
  CLI arg, or transmit them. They live in `ATXP_CONNECTION` / `~/.atxp/config`, both
  gitignored.
- Default new code to idiomatic Go; the existing client is dependency-light (stdlib +
  `github.com/modelcontextprotocol/go-sdk`). The hosted-account path does **no on-chain
  crypto** — keep it that way; settlement is delegated to ATXP over HTTP.

## State of play

- **Client (done, validated live against production):** root package `atxp` —
  `account.go`, `oauth.go`, `store.go`, `transport.go`, `client.go` (+ `atxp_test.go`,
  `live_test.go`). Connects to paid ATXP MCP servers; handles OAuth (discovery, dynamic
  client registration, PKCE, the ATXP `/sign` + `redirect=false` authorization trick) and
  per-call payment (omni-challenge → `/authorize/auto` → header retry) transparently.
- **Server / merchant (NOT built — this is the task):** `server/` is an empty stub.
  Goal: let a Go MCP server charge its callers over ATXP (alongside any existing rails),
  by emitting omni-challenges and verifying/settling payments.

## The task: port the merchant side

Read `docs/PLAN.md` first — it has the TS→Go package map and build order. `docs/PROTOCOL.md`
has the wire protocol (OAuth + payment flow, endpoint table). Key finding: the merchant side
is **also crypto-free** — `ATXPPaymentServer` delegates `/charge`, `/payment-request`,
`/balance` to ATXP over HTTP; the only local crypto is an HMAC (`opaqueIdentity`).

The authoritative reference is the TS source. It is NOT vendored here. Re-clone it:

```
git clone --depth 1 https://github.com/atxp-dev/sdk /tmp/atxp-sdk
```

Then read, in `packages/atxp-server/src/`: `requirePayment.ts`, `omniChallenge.ts`,
`paymentServer.ts`, `opaqueIdentity.ts`, `protocol.ts`, and `core/oauth.ts` + `token.ts`
for the resource-server (token-introspection) side. Port faithfully — reinventing payment
verification is how you accidentally give service away free.

Suggested build order (also in PLAN.md): `paymentserver.go` (HTTP client) → `opaqueidentity.go`
(HMAC) → `omnichallenge.go` (data assembly; port the USDC-address / CAIP2 / decimals tables
verbatim) → `requirepayment.go` (the gate) → resource-server OAuth/token introspection. Add
httptest unit tests per file and a `serverlive`-tagged test that issues a real challenge and
settles a real payment (needs a funded account).

## Build & test

```
go build ./...
go test ./...                                 # unit, no network
go test -tags atxplive -run TestLive ./...    # live; needs funded ATXP_CONNECTION
```

A freshly `npx atxp@latest agent register`-ed account is an **orphan**, unfunded, and
`fraud_blocked` — it cannot `/sign` or pay. The web `/fund` page funds the email-login
*owner* account, not the orphan. Use a funded account's connection string from the
dashboard **Servers** page (`funded: true`). See `docs/PROTOCOL.md`.

## Out of scope

gemot's integration (wiring this into gemot's `internal/payments`, deciding which tools to
meter, the prepay-credit ledger) is gemot's job, not chit's. chit stays a general-purpose
module.
