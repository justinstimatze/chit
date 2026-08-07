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
- **Server / merchant (done):** `server/` package. `RequirePayment` gates a metered call
  (on-demand `/charge`, falling back to an omni-challenge); `CheckToken`/`CheckRequest`
  authenticate callers (RFC 7662 introspection); `Verify`/`Settle` finalize a push-payment
  retry credential. Also ported from later upstream commits: the x402 `upto` scheme and MPP
  Tempo/Solana `session`-intent challenges (advertised when the auth server supports them),
  and an explicit `PaymentSession` (`Merchant.OpenPaymentSession`/`CloseSession`) so several
  `RequirePayment` calls sharing one retry credential can charge locally and settle once, for
  the metered actual rather than the credential's full cap — the Go equivalent of upstream's
  Express-middleware session-close settlement, since chit has no middleware layer to open/close
  it implicitly.
- **Self-custodial x402 signing (done, live-verified):** `x402signer/` — an `atxp.Account`
  implementation that pays an x402 "exact"-scheme challenge by signing an EIP-3009
  `transferWithAuthorization` with a raw secp256k1 key (no RPC, no gas, no broadcast — it only
  signs). New dependency: `github.com/ethereum/go-ethereum` (isolated to this subpackage so the
  root package's dependency graph is unaffected). Built because the hosted/ATXP-native rail
  turns out to be restricted to ATXP's own first-party services for real settlement — see
  `docs/PROTOCOL.md`'s IOU-conversion notes; x402/MPP are the actual third-party-payment rails.
  Real settlement confirmed on Base mainnet, verified via the on-chain `Transfer` event log
  (see `docs/PROTOCOL.md`'s payment-modes table), including the true stranger-to-stranger case
  with no ATXP account on the payer side at all (`examples/x402stranger`). `atxp.HybridAccount`
  pairs an `ATXPAccount`'s OAuth identity with an `x402signer` account's payment signing, for
  when a resource is gated behind an OAuth 401 rather than a bare 402. Scope: EVM "exact" only.
  Not done: `upto`/Permit2, Solana, MPP, any keystore/KMS.

## Keeping in sync with upstream

chit tracks `atxp-dev/sdk` (TS) by re-reading it periodically, not via a dependency pin — it
is not vendored. To check for drift:

```
git clone --depth 50 https://github.com/atxp-dev/sdk /tmp/atxp-sdk-check
cd /tmp/atxp-sdk-check && git log --oneline -20 -- packages/atxp-server/src packages/atxp-client/src
```

Read new commits' diffs directly (`git show <sha>`) rather than trusting commit-message
summaries alone — the wire contract details (which field is atomic vs decimal, which scheme
gates which override) live in the diff, not the message. Skip anything under `atxp-base`/
`atxp-x402` self-custody signer paths — chit's client only implements the hosted `ATXPAccount`
path (see `docs/PROTOCOL.md`'s Scope decision), so self-custody-only changes don't apply.

Port order for a new merchant-side feature: `packages/atxp-server/src/omniChallenge.ts` (data
assembly) → `protocol.ts` (settle-body / detection changes) → `paymentSession.ts` (if it's a
metering change) → `requirePayment.ts` (wiring). Match `server/omnichallenge.go` →
`server/protocol.go` → `server/paymentsession.go` → `server/requirepayment.go` respectively.
Port faithfully — reinventing payment verification is how you accidentally give service away
free.

## Build & test

```
go build ./...
go test ./...                                    # unit, no network
go test -tags atxplive -run TestLive ./...       # client live; needs funded ATXP_CONNECTION
go test -tags serverlive -run TestLive ./server/... # merchant live; needs funded ATXP_CONNECTION
```

CI (`.github/workflows/ci.yml`) runs build/vet/gofmt/test/golangci-lint, plus
`govulncheck`, `gitleaks`, and `semgrep` as separate jobs. Mirror the fast
checks locally before pushing: `git config core.hooksPath scripts/githooks`
once, then `scripts/githooks/pre-commit` runs on every commit.

A freshly `npx atxp@latest agent register`-ed account is an **orphan**, unfunded, and
`fraud_blocked` — it cannot `/sign` or pay. The web `/fund` page funds the email-login
*owner* account, not the orphan. Use a funded account's connection string from the
dashboard **Servers** page (`funded: true`). See `docs/PROTOCOL.md`.

## Out of scope

Integrating chit into any specific downstream application (deciding which tools to meter,
how to credit a ledger, what to charge) is that application's job, not chit's. chit stays a
general-purpose module.
