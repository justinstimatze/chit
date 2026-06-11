# chit — plan for an unofficial Go module for ATXP

## Goal & positioning

A standalone, reusable Go module for ATXP (client + merchant/server), since no Go
implementation exists anywhere — only the official TypeScript SDK (`github.com/atxp-dev/sdk`,
MIT, © 2025 Circuit and Chisel). gemot imports it; others can too.

**Unofficial.** Not affiliated with or endorsed by Circuit & Chisel. Steps to keep that
clear and compliant:
- Repo under a personal namespace, e.g. `github.com/justinstimatze/chit` — the import
  path itself signals non-official.
- README title: "Unofficial Go client for ATXP." First line: not affiliated/endorsed;
  link the official TS SDK + docs.atxp.ai.
- Retain the MIT notice + "Copyright (c) 2025 Circuit and Chisel" (port of MIT code → must
  attribute). Add our own copyright for new code.
- Descriptive use of the name "ATXP" only; never title it "the ATXP Go SDK" or use their
  marks/logo. MIT licenses the code, not the trademark.

## Module layout

```
chit/
  client/        # DONE — extracted from gemot internal/atxp (account, oauth, store, transport, client)
  server/        # TO BUILD — merchant side
  common/        # shared: types, USDC addresses, CAIP2 maps, decimals, networks
  LICENSE        # MIT, retains Circuit & Chisel copyright + ours
  README.md      # unofficial disclaimer + quickstart
  examples/
```

gemot consumes `client` (spend, later) and `server` (charge clients, now).

## Client — status: DONE, fully validated live

Built/tested in gemot `internal/atxp`; to be moved to `chit/client`. Proven end-to-end
against prod (discovery→DCR→/me→/sign→/authorize/auto→payment→real search). Crypto-free
hosted-account model. See ATXP_GO_HANDOFF.md.

## Server / merchant — TO BUILD (the new work)

Key finding from reading the TS server source: **crypto-free, like the client.** Settlement
and credential verification are delegated to ATXP's payment server over HTTP; the only local
crypto is an HMAC. No go-ethereum / solana-go.

TS → Go package map (source: `atxp-sdk/packages/atxp-server/src`):

| TS file | Go package | Does |
|---|---|---|
| `paymentServer.ts` (`ATXPPaymentServer`) | `server` | HTTP client to ATXP auth server: `POST /charge` (200/202 ok, 402 = unpaid), `POST /payment-request` → id, `POST /balance` |
| `omniChallenge.ts` | `server` (`omnichallenge.go`) | Build the multi-rail challenge: x402 `accepts[]` (Base/Solana, USDC addresses, CAIP2 networks, 6-decimals, amount×1e6) + MPP challenges (solana/tempo) + atxp data; emit as MCP error `-30402`/`-32042` |
| `opaqueIdentity.ts` | `server` (`opaqueidentity.go`) | HMAC-SHA256 sign/verify of `{atxp_sub, sig}` over `sub:challengeId`; binds OAuth identity into MPP `opaque` field so it survives the `Authorization: Payment` retry. Key from `ATXP_OPAQUE_KEY` (base64) or random-per-process. stdlib `crypto/hmac`,`crypto/sha256` |
| `requirePayment.ts` | `server` (`requirepayment.go`) | The gate: compute amount (max of minimum & price); try `paymentServer.charge()` (on-demand, if caller token present); else `createPaymentRequest()` + throw omni-challenge advertising all rails |
| `core/oauth.ts`, `token.ts`, `oAuthMetadata.ts`, `protectedResourceMetadata.ts` | `server` (`oauth.go`) | Resource-server side: serve `/.well-known/oauth-protected-resource`, validate/introspect the caller's bearer token against ATXP (reuse client's `OAuthResourceClient` introspection) |
| `protocol.ts` | `common` | `OmniChallenge`, `X402PaymentRequirements`, `MppChallengeData`, `AtxpMcpChallengeData` types |

Settlement-on-retry note: in the TS SDK the Express middleware credits the ledger before the
route runs; the route's `requirePayment` then sees the charge already settled. In gemot the
equivalent is: verify the credential on the retry (recover identity via opaque HMAC + confirm
payment via ATXP `/charge` or payment-request status), then proceed.

## gemot integration (hand to the gemot session — couples to internal/payments + MCP server)

- Call the `requirePayment` equivalent before the metered MCP tool. Given gemot's prepay
  model, meter a `buy_credits` tool (agent's wallet settles it → credit the existing ledger),
  rather than per-`analyze` — keeps multi-call deliberations from re-paying. Per-call is also
  possible if desired.
- Charge amount from `internal/cost` (operating-cost estimate + thin margin).
- Credit the existing `internal/payments` ledger; `analyze` keeps drawing it down unchanged.
- Result: one merchant integration, three inbound rails — MPP (existing Stripe), x402, and
  atxp-native — with ATXP settling x402/atxp on-chain. Stripe path unchanged. gemot writes
  no on-chain code and runs no facilitator.

## Build order

1. Extract `internal/atxp` → `chit/client` + `common`; add LICENSE/README/disclaimer.
2. `server`: `paymentserver.go` (HTTP) → `opaqueidentity.go` (HMAC) → `omnichallenge.go`
   (data assembly; port USDC/CAIP2 tables verbatim) → `requirepayment.go` (gate) →
   resource-server OAuth (token introspection).
3. Unit tests (httptest) for each; a `serverlive`-tagged test that issues a real challenge
   and settles a real payment against prod (needs the funded account).
4. gemot session: wire `requirePayment` into the `buy_credits` MCP handler; connect cost →
   amount and ledger crediting.

## Open item for the user
- Confirm repo name `chit` (vs a codename). Recommendation: `chit` — discoverable for
  the stated "easy for others" goal; namespace + disclaimer handle the unofficial framing.
