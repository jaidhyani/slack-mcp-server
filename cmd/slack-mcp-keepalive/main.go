// Command slack-mcp-keepalive force-refreshes the rotating OAuth credential
// file so the refresh chain stays alive when the MCP server is idle for long
// stretches. Designed to be invoked from cron alongside other nightly jobs.
//
// One invocation refreshes one credential file. To keep multiple workspaces
// alive, invoke once per cred file (see scripts/slack-mcp-keepalive.sh in
// clai for the multi-workspace wrapper).
//
// Usage:
//
//	slack-mcp-keepalive \
//	    --client-id "$SLACK_MCP_OAUTH_CLIENT_ID" \
//	    --client-secret "$SLACK_MCP_OAUTH_CLIENT_SECRET" \
//	    --cred-file "$SLACK_MCP_OAUTH_CRED_FILE"
//
// Exit codes:
//
//	0   refresh succeeded (or, with --if-due, no refresh was needed)
//	1   transient failure (network, 5xx, rate limit)
//	2   bad flags / cred-file load failure
//	3   refresh token rejected by Slack (terminal — re-bootstrap required)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/korotovsky/slack-mcp-server/pkg/rotator"
	"go.uber.org/zap"
)

func main() {
	var (
		clientID     string
		clientSecret string
		credFile     string
		ifDue        bool
		timeout      time.Duration
	)
	flag.StringVar(&clientID, "client-id", "", "Slack app client ID (required)")
	flag.StringVar(&clientSecret, "client-secret", "", "Slack app client secret (required)")
	flag.StringVar(&credFile, "cred-file", "", "credential file path (required)")
	flag.BoolVar(&ifDue, "if-due", false, "only refresh if within RefreshLead of expiry; default forces a refresh")
	flag.DurationVar(&timeout, "timeout", 30*time.Second, "refresh request timeout")
	flag.Parse()

	if clientID == "" || clientSecret == "" || credFile == "" {
		fmt.Fprintln(os.Stderr, "client-id, client-secret, and cred-file are required")
		flag.Usage()
		os.Exit(2)
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	rot, err := rotator.New(rotator.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		FilePath:     credFile,
		Logger:       logger,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "load rotator: %v\n", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var refreshErr error
	if ifDue {
		refreshErr = rot.RefreshIfDue(ctx)
	} else {
		refreshErr = rot.RefreshNow(ctx)
	}

	if refreshErr == nil {
		snap := rot.Snapshot()
		fmt.Fprintf(os.Stderr, "ok: team=%s expires_at=%s\n",
			snap.TeamID, snap.ExpiresAt.Format(time.RFC3339))
		return
	}
	if errors.Is(refreshErr, rotator.ErrInvalidGrant) {
		fmt.Fprintf(os.Stderr, "fatal: refresh token rejected (re-bootstrap required): %v\n", refreshErr)
		os.Exit(3)
	}
	fmt.Fprintf(os.Stderr, "transient: %v\n", refreshErr)
	os.Exit(1)
}
