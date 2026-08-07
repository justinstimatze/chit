# chit

**Unofficial Go client and merchant library for [ATXP](https://docs.atxp.ai).**
Not affiliated with, authorized by, or endorsed by Circuit & Chisel — the
makers of ATXP. For the official, supported SDK, use their TypeScript one:
https://github.com/atxp-dev/sdk

`chit` lets a Go program act as an ATXP **client** (pay for MCP tools) and/or
a **merchant** (charge callers for MCP tools), including self-custodial x402
payments that need no ATXP account at all on the paying side.

The module path is a codename (`chit`) but the package is `atxp`, so it reads
naturally:

```go
import "github.com/justinstimatze/chit"

c, _ := atxp.New(atxp.Config{ConnectionString: os.Getenv("ATXP_CONNECTION")})
sess, _ := c.Connect(ctx, "https://search.mcp.atxp.ai/")
res, _ := sess.CallTool(ctx, &mcp.CallToolParams{
    Name:      "search_search",
    Arguments: map[string]any{"query": "..."},
})
```

The hosted-account client path does **no on-chain crypto**: signing and
settlement are delegated to ATXP over HTTP. A connection string is a
**wallet-grade secret** — never log it, pass it as a CLI argument, or send it
anywhere. `x402signer/` is the exception: it signs EIP-3009 authorizations
directly with a raw secp256k1 key, isolated to its own subpackage so the root
package's dependency graph stays crypto-free.

## Status

- **Client** — done, validated end-to-end against production (discovery,
  dynamic client registration, OAuth, `/sign`, `/authorize/auto`, payment
  retry, a real paid tool call). Lives at the module root (`package atxp`).
- **Server / merchant** — done. `server.RequirePayment` gates a metered call;
  `CheckToken`/`CheckRequest` authenticate callers; `Verify`/`Settle` finalize
  a push-payment retry credential; `Merchant.OpenPaymentSession`/
  `CloseSession` let several calls sharing one retry credential settle once.
- **Self-custodial x402 signing** (`x402signer/`) — done, live-verified. Pays
  an x402 "exact"-scheme challenge by signing an EIP-3009
  `transferWithAuthorization` with a raw key, no ATXP account, no OAuth, no
  prior relationship with the merchant required. Real settlement confirmed
  on Base mainnet, verified via the chain's own `Transfer` event log, not
  just an API response. `atxp.HybridAccount` pairs this with an
  `ATXPAccount`'s OAuth identity for resources gated behind an OAuth 401
  rather than a bare 402.

See `docs/PROTOCOL.md`'s payment-modes table for exactly which combinations
of payer identity, destination, and resource gate actually settle real money,
with sequence diagrams for each.

## Examples

- `examples/paidmcp` — an OAuth-gated MCP server charging $0.01 per tool call,
  plus a client that pays it. Demonstrates the hosted-account and hybrid x402
  paths.
- `examples/x402stranger` — a bare-402 merchant and a client with no ATXP
  account at all, demonstrating true stranger-to-stranger payment.

## Testing

```
go build ./...
go test ./...                                        # unit, no network
go test -tags atxplive -run TestLive ./...            # client live; needs funded ATXP_CONNECTION
go test -tags serverlive -run TestLive ./server/...   # merchant live; needs funded ATXP_CONNECTION
```

The live tests need a funded ATXP account connection string, read from
`ATXP_CONNECTION` or `~/.atxp/config`. A freshly `agent register`-ed account
is unfunded and fraud-blocked; use a funded account's connection string from
the dashboard **Servers** page instead. See `docs/PROTOCOL.md` for the full
account-model details.

## Docs

- `docs/PROTOCOL.md` — the ATXP wire protocol as reverse-engineered from the
  TS SDK: the OAuth + payment flow, endpoint table, and every payment mode
  that's actually been tested live, with sequence diagrams.

## License

MIT. This is a port of Circuit & Chisel's MIT-licensed TypeScript SDK; their
copyright notice is retained in `LICENSE`. Contact: justin@justinstimatze.com
