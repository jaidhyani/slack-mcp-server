# OAuth Token Rotation (work in progress)

## Why

The official `mcp.slack.com` server issues 1-hour OAuth access tokens with **no
refresh token**, forcing browser-based re-auth multiple times per day. See
upstream tracking: [anthropics/claude-code#26281](https://github.com/anthropics/claude-code/issues/26281),
[#29257](https://github.com/anthropics/claude-code/issues/29257).

This server already supports static `xoxp-` user tokens, but those don't rotate
either — they're long-lived but a leaked one is valid until manually revoked.

This change adds a fourth auth backend that holds Slack OAuth refresh-token
material and refreshes the access token in the background, giving fully
unattended operation while still using rotated (short-lived) tokens.

## Auth backends

| Mode | Env vars | Lifecycle |
|---|---|---|
| `xoxc` + `xoxd` | `SLACK_MCP_XOXC_TOKEN`, `SLACK_MCP_XOXD_TOKEN` | Browser session — until cookie revoked |
| `xoxp` (static) | `SLACK_MCP_XOXP_TOKEN` | Long-lived, no rotation |
| `xoxb` (static) | `SLACK_MCP_XOXB_TOKEN` | Long-lived, no rotation |
| **`oauth-rotating` (new)** | `SLACK_MCP_OAUTH_CLIENT_ID`, `SLACK_MCP_OAUTH_CLIENT_SECRET`, `SLACK_MCP_OAUTH_CRED_FILE` | Short-lived, automatically rotated |

Selection priority when multiple are set: `oauth-rotating` > `xoxp` > `xoxb` >
`xoxc`/`xoxd` (matches existing behavior with the new mode taking top priority).

## Slack app prerequisites (one-time)

The Slack app must have **Token Rotation** enabled in its config. Note that
this toggle is one-way per [Slack docs](https://docs.slack.dev/authentication/using-token-rotation/) —
once enabled, it cannot be disabled for that app. Use a fresh app for this
mode.

Required granular scopes mirror the read-mostly tools the existing static-xoxp
mode uses; see `docs/04-permissions.md` for the canonical list.

## Credential file format

Stored at the path given by `SLACK_MCP_OAUTH_CRED_FILE` (default: `$XDG_DATA_HOME/slack-mcp-server/<team_id>.json`).

```json
{
  "version": 1,
  "team_id": "T012ABCDEFG",
  "user_id": "U012ABCDEFG",
  "access_token": "xoxe.xoxp-1-...",
  "refresh_token": "xoxe-1-...",
  "expires_at": "2026-04-30T23:00:00Z",
  "scope": "search:read,channels:history,im:history,..."
}
```

Writes are atomic (write-to-temp + rename) and serialized via a per-file
`flock(2)` so concurrent server processes don't double-refresh and clobber
each other's state.

## Refresh policy

- A background goroutine wakes every minute and checks `expires_at`.
- If the token is within `refresh_lead_time` (default 10 min) of expiring, it
  calls `oauth.v2.access` with `grant_type=refresh_token`.
- A successful refresh writes a new `access_token`, `refresh_token`, and
  `expires_at` to the credential file (atomically).
- On `invalid_grant` or any other terminal error, the rotator stops trying and
  surfaces a clear error: re-bootstrap is required.
- Transient errors (network, 5xx, rate limits) retry with exponential backoff;
  the access token in memory remains valid until its real expiry.

## Bootstrap (`slack-mcp-oauth-init`)

Single one-time interactive flow:

```bash
slack-mcp-oauth-init \
  -client-id $SLACK_MCP_OAUTH_CLIENT_ID \
  -client-secret $SLACK_MCP_OAUTH_CLIENT_SECRET \
  -redirect-uri http://localhost:3119/callback \
  -out $SLACK_MCP_OAUTH_CRED_FILE
```

Steps:
1. Spin up a local HTTP listener on the redirect URI.
2. Print the authorize URL; user opens it in a browser.
3. Receive the callback with `code`.
4. Exchange `code` for `access_token` + `refresh_token` via `oauth.v2.access`.
5. Persist to credential file.
6. Exit. The user then starts the server normally with the env vars pointing
   at the cred file.

### Redirect URI: dev (localhost) vs. distribution (HTTPS)

Slack's OAuth requirements for the redirect URI differ depending on context:

- **Dev / self-host single-user:** `http://localhost:3119/callback` works
  fine. The listener and your browser are on the same machine; no reverse
  proxy is needed.
- **App Directory submission / multi-user distribution:** Slack requires the
  redirect URI to be **HTTPS** and **publicly reachable** (no `localhost`,
  no plain HTTP). Register something like
  `https://<your-host>/slack-oauth/callback` on the Slack app's OAuth
  config and front it with a TLS-terminating reverse proxy that forwards to
  the bootstrap listener on `localhost:3119`.

In both cases the `-redirect-uri` you pass to `slack-mcp-oauth-init` must
**exactly match** one of the Redirect URLs configured on the Slack app. The
`-listen` flag lets the listener bind to a different address than the public
redirect URI advertises — useful when a reverse proxy fronts a public HTTPS
endpoint:

```bash
slack-mcp-oauth-init \
  -client-id $SLACK_MCP_OAUTH_CLIENT_ID \
  -client-secret $SLACK_MCP_OAUTH_CLIENT_SECRET \
  -redirect-uri https://your-host.example.com/slack-oauth/callback \
  -listen localhost:3119 \
  -out $SLACK_MCP_OAUTH_CRED_FILE
```

(When `-listen` is omitted, the binary defaults to the redirect URI's
host:port for localhost redirects, and `localhost:3119` otherwise.)

### Forcing a specific workspace

When the browser is signed into multiple Slack workspaces, Slack's OAuth
landing page picks one by default — which may not be the one you want to
install into. Pass `-team T01ABCDE` (the target workspace's `team_id`) to
force the workspace selector. Without it, you may land on a "redirect_uri
did not match any configured URIs" error because the chosen workspace
doesn't host the app.

### Example reverse proxy (Caddy)

Drop this into a Caddy site block on the host whose hostname matches the
HTTPS redirect URI you registered:

```caddyfile
your-host.example.com {
    # Slack OAuth callback proxy — forwards to slack-mcp-oauth-init's
    # localhost:3119 listener during bootstrap. Slack distribution requires
    # HTTPS for the redirect URI; this provides it. Use `handle` (not
    # `handle_path`) so the path /slack-oauth/callback is preserved when
    # forwarded — the bootstrap binary registers its handler at the full
    # redirect-uri path.
    handle /slack-oauth/* {
        reverse_proxy localhost:3119
    }

    # ... your other handlers
}
```

The proxy only needs to be reachable while the bootstrap is running; it
plays no role at runtime after the cred file is written. Leaving it
configured is harmless and lets future re-bootstraps use the same flow.

## Keepalive — when the server is idle for long stretches

Slack rotating refresh tokens have a finite lifetime per refresh: if the
server is never started during that window, the refresh chain dies and the
operator must re-bootstrap by hand. The background loop only refreshes
*while the server is running*, so a server that is only started on-demand
(e.g. once per Claude Code session) can be too idle to keep the chain
alive.

Two mitigations:

1. **`slack-mcp-keepalive` cron**: a sibling binary that does one
   force-refresh per invocation. Run it from cron (nightly is usually
   plenty — the access TTL is 12h, refresh tokens are valid considerably
   longer):

   ```bash
   slack-mcp-keepalive \
     -client-id $SLACK_MCP_OAUTH_CLIENT_ID \
     -client-secret $SLACK_MCP_OAUTH_CLIENT_SECRET \
     -cred-file $SLACK_MCP_OAUTH_CRED_FILE
   ```

   Exit codes: `0` success, `1` transient failure, `3` terminal failure
   (re-bootstrap required).

2. **Synchronous startup refresh**: when `slack-mcp-server` starts and the
   cred file is already past `RefreshLead`, it now refreshes **before** the
   first auth-validation call. This avoids the goroutine race where the
   validator hit Slack with the stale token and fatal'd before the
   background loop had a chance to refresh.

## Wiring into MCPSlackClient

This is the part that makes the existing code rotation-aware. `slack.Client`
captures its token at `slack.New(token, ...)` and does not re-read it. To
support in-place rotation, `MCPSlackClient.slackClient` and `.edgeClient`
become `atomic.Pointer[T]`. When the rotator commits a new token, it
reconstructs both clients with the new token and atomically swaps the
pointers. All `c.slackClient.Method()` callsites become `c.sc().Method()`
where `sc()` does the atomic load.

This is a mechanical change across ~25 sites in `pkg/provider/api.go` and a
handful in the edge client wrapper.

## Implementation plan

1. ✅ `pkg/rotator/rotator.go` — pure refresh + disk-persistence logic, testable
   against a fake `oauth.v2.access` endpoint. **(this slice)**
2. `pkg/auth/rotating.go` — implement `slackdump/v3/auth.Provider` on top of
   `pkg/rotator`.
3. `MCPSlackClient` rotation: switch slackClient/edgeClient to `atomic.Pointer`;
   subscribe to rotator updates and rebuild on rotation.
4. `cmd/slack-mcp-server/oauth_init.go` — bootstrap subcommand.
5. Wire into `provider.New()` priority chain.
6. End-to-end test against a real Slack workspace.
7. Upstream PR.

## Non-goals

- Multi-user OAuth (covered by [PR #166](https://github.com/korotovsky/slack-mcp-server/pull/166)).
  This change is single-user; one cred file = one workspace identity.
- Browser cookie session refresh (`xoxc`/`xoxd`) — different mechanism, out of
  scope.
