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

## Bootstrap (`oauth-init` subcommand)

Single one-time interactive flow:

```bash
slack-mcp-server oauth-init \
  --client-id $SLACK_MCP_OAUTH_CLIENT_ID \
  --client-secret $SLACK_MCP_OAUTH_CLIENT_SECRET \
  --redirect-uri http://localhost:3119/callback \
  --scopes search:read,channels:history,...
```

Steps:
1. Spin up a localhost HTTP listener on the redirect URI.
2. Print the authorize URL; user opens it in a browser.
3. Receive the callback with `code`.
4. Exchange `code` for `access_token` + `refresh_token` via `oauth.v2.access`.
5. Persist to credential file.
6. Exit. The user then starts the server normally with the env vars pointing
   at the cred file.

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
