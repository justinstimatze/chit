# chit

**Unofficial Go client for [ATXP](https://docs.atxp.ai).** Not affiliated with,
authorized by, or endorsed by Circuit & Chisel — the makers of ATXP. For the
official, supported SDK, use their TypeScript one: https://github.com/atxp-dev/sdk

`chit` lets a Go program act as an ATXP **client** — connect to paid ATXP MCP tool
servers (web search, image/video/music generation, etc.) using a hosted-account
connection string, with OAuth and per-call payments handled transparently. A
**server/merchant** side (charge your own callers) is in progress; see `docs/PLAN.md`.

The module path is a codename (`chit`) but the package is `atxp`, so it reads naturally:

```go
import "github.com/justinstimatze/chit"

c, _ := atxp.New(atxp.Config{ConnectionString: os.Getenv("ATXP_CONNECTION")})
sess, _ := c.Connect(ctx, "https://search.mcp.atxp.ai/")
res, _ := sess.CallTool(ctx, &mcp.CallToolParams{
    Name:      "search_search",
    Arguments: map[string]any{"query": "..."},
})
```

It does **no on-chain crypto**: the hosted-account model delegates all signing and
settlement to ATXP over HTTP. A connection string is a **wallet-grade secret** —
never log it, pass it as a CLI argument, or send it anywhere.

## Status

- **Client** — done, validated end-to-end against production (discovery, dynamic
  client registration, OAuth, `/sign`, `/authorize/auto`, payment retry, a real
  paid tool call). Lives at the module root (`package atxp`).
- **Server / merchant** — not built yet (`server/`). See `docs/PLAN.md`.

## Testing

```
go test ./...                                   # unit tests (httptest, no network)
go test -tags atxplive -run TestLive ./...      # live tests against prod
```

The live tests need a funded ATXP account connection string, read from
`ATXP_CONNECTION` or `~/.atxp/config`. Note that a freshly `agent register`-ed
account is unfunded and fraud-blocked; use a funded account's connection string
from the dashboard. See `docs/PROTOCOL.md` for the account-model details.

## Docs

- `docs/PROTOCOL.md` — the ATXP wire protocol as reverse-engineered from the TS SDK,
  with the OAuth + payment flow and endpoint table.
- `docs/PLAN.md` — the module plan and the server/merchant port map (TS → Go).

## License

MIT. This is a port of Circuit & Chisel's MIT-licensed TypeScript SDK; their
copyright notice is retained in `LICENSE`. Contact: justin@justinstimatze.com
