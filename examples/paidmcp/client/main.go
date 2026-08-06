// Command paidmcp-client drives the payer side of the examples/paidmcp demo:
// connects to a running paidmcp server over ATXP and calls its "ping" tool,
// paying for it via the full OAuth + payment retry flow.
//
// Usage:
//
//	ATXP_CONNECTION=<payer connection string> \
//	go run ./examples/paidmcp/client https://<host>.<tailnet>.ts.net/mcp
package main

import (
	"context"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	atxp "github.com/justinstimatze/chit"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: paidmcp-client <resource-url>")
	}
	resourceURL := os.Args[1]

	conn := os.Getenv("ATXP_CONNECTION")
	if conn == "" {
		log.Fatal("ATXP_CONNECTION not set (payer's connection string)")
	}

	ctx := context.Background()

	c, err := atxp.New(atxp.Config{ConnectionString: conn})
	if err != nil {
		log.Fatalf("atxp.New: %v", err)
	}

	sess, err := c.Connect(ctx, resourceURL)
	if err != nil {
		log.Fatalf("Connect: %v", err)
	}
	defer sess.Close()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "ping", Arguments: map[string]any{}})
	if err != nil {
		log.Fatalf("CallTool: %v", err)
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			log.Printf("result: %s", tc.Text)
		}
	}
	log.Println("PAID CALL SUCCEEDED")
}
