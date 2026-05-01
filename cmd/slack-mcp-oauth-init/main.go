// Command slack-mcp-oauth-init runs the one-time OAuth bootstrap for a Slack
// app with token rotation enabled. It opens a local HTTP listener for the
// redirect URI, prints an authorize URL for the user to open in their
// browser, exchanges the resulting `code` for an access_token + refresh_token,
// and writes the credential file in the format pkg/rotator consumes.
//
// Usage:
//
//	slack-mcp-oauth-init \
//	    --client-id "$SLACK_MCP_OAUTH_CLIENT_ID" \
//	    --client-secret "$SLACK_MCP_OAUTH_CLIENT_SECRET" \
//	    --redirect-uri http://localhost:3119/callback \
//	    --scopes search:read,channels:history,im:history,... \
//	    --out "$SLACK_MCP_OAUTH_CRED_FILE"
//
// The redirect URI must exactly match a redirect URL registered on the
// Slack app. The default port 3119 is registered on the Slack apps the
// slack-mcp-server team maintains; use a different port only if you've
// registered it on your app.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const oauthAuthorizeURL = "https://slack.com/oauth/v2/authorize"
const oauthAccessURL = "https://slack.com/api/oauth.v2.access"

func main() {
	var (
		clientID     string
		clientSecret string
		redirectURI  string
		scopes       string
		userScopes   string
		outPath      string
		timeout      time.Duration
	)
	flag.StringVar(&clientID, "client-id", "", "Slack app client ID (required)")
	flag.StringVar(&clientSecret, "client-secret", "", "Slack app client secret (required)")
	flag.StringVar(&redirectURI, "redirect-uri", "http://localhost:3119/callback", "OAuth redirect URI (must match the Slack app config)")
	flag.StringVar(&scopes, "scopes", "", "comma-separated bot scopes (passed to scope=)")
	flag.StringVar(&userScopes, "user-scopes", "channels:history,channels:read,groups:history,groups:read,im:history,im:read,im:write,mpim:history,mpim:read,mpim:write,users:read,users:read.email,chat:write,search:read,reactions:write,usergroups:read,usergroups:write", "comma-separated user scopes (passed to user_scope=)")
	flag.StringVar(&outPath, "out", "", "credential file output path (required)")
	flag.DurationVar(&timeout, "timeout", 5*time.Minute, "how long to wait for the OAuth callback")
	flag.Parse()

	if clientID == "" || clientSecret == "" || outPath == "" {
		fmt.Fprintln(os.Stderr, "client-id, client-secret, and out are required")
		flag.Usage()
		os.Exit(2)
	}

	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil {
		exitf("invalid redirect-uri: %v", err)
	}
	if parsedRedirect.Hostname() != "localhost" && parsedRedirect.Hostname() != "127.0.0.1" {
		exitf("redirect-uri must point to localhost; got %q", parsedRedirect.Hostname())
	}

	// State token for CSRF protection.
	state := randHex(16)

	// Build the authorize URL.
	authU := mustParseURL(oauthAuthorizeURL)
	q := authU.Query()
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	if scopes != "" {
		q.Set("scope", scopes)
	}
	if userScopes != "" {
		q.Set("user_scope", userScopes)
	}
	authU.RawQuery = q.Encode()

	// Bind the local listener.
	listenAddr := parsedRedirect.Host
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		exitf("listen %s: %v", listenAddr, err)
	}
	defer ln.Close()

	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc(parsedRedirect.Path, func(w http.ResponseWriter, r *http.Request) {
		gotState := r.URL.Query().Get("state")
		if gotState != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			errCh <- fmt.Errorf("state mismatch (expected %q, got %q)", state, gotState)
			return
		}
		if oauthErr := r.URL.Query().Get("error"); oauthErr != "" {
			http.Error(w, "oauth error: "+oauthErr, http.StatusBadRequest)
			errCh <- fmt.Errorf("oauth provider returned error: %s", oauthErr)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			errCh <- errors.New("callback missing code")
			return
		}
		fmt.Fprintln(w, "OAuth flow complete. You can close this window.")
		codeCh <- code
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	fmt.Fprintln(os.Stderr, "==>")
	fmt.Fprintln(os.Stderr, "==> Open this URL in your browser to authorize:")
	fmt.Fprintln(os.Stderr, "==>")
	fmt.Fprintln(os.Stderr, "    "+authU.String())
	fmt.Fprintln(os.Stderr, "==>")
	fmt.Fprintf(os.Stderr, "==> Waiting on callback at %s (timeout: %s)\n", redirectURI, timeout)

	var code string
	select {
	case code = <-codeCh:
	case err = <-errCh:
		exitf("callback error: %v", err)
	case <-time.After(timeout):
		exitf("timeout waiting for callback")
	}

	creds, err := exchangeCode(clientID, clientSecret, redirectURI, code)
	if err != nil {
		exitf("exchange code: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
		exitf("mkdir cred dir: %v", err)
	}

	out, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		exitf("marshal creds: %v", err)
	}
	tmp := outPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		exitf("write %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, outPath); err != nil {
		exitf("rename to %s: %v", outPath, err)
	}

	fmt.Fprintln(os.Stderr, "==>")
	fmt.Fprintf(os.Stderr, "==> Wrote credentials to %s\n", outPath)
	fmt.Fprintf(os.Stderr, "==> team_id=%s user_id=%s expires_in=%s\n",
		creds.TeamID, creds.UserID, time.Until(creds.ExpiresAt).Round(time.Second))
}

type credFile struct {
	Version      int       `json:"version"`
	TeamID       string    `json:"team_id"`
	UserID       string    `json:"user_id,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope,omitempty"`
}

// oauth.v2.access response. Slack's response varies: when user_scope is
// requested, the user-level token lives under `authed_user`. When only bot
// scopes are requested, `access_token` is the bot token at the top level.
// We support both shapes; for rotation, the relevant token is the one with
// a refresh_token + expires_in.
type accessResp struct {
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	Team         struct {
		ID string `json:"id"`
	} `json:"team"`
	AuthedUser struct {
		ID           string `json:"id"`
		AccessToken  string `json:"access_token,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
		ExpiresIn    int64  `json:"expires_in,omitempty"`
		Scope        string `json:"scope,omitempty"`
		TokenType    string `json:"token_type,omitempty"`
	} `json:"authed_user"`
}

func exchangeCode(clientID, clientSecret, redirectURI, code string) (*credFile, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)

	req, err := http.NewRequest(http.MethodPost, oauthAccessURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	httpc := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var ar accessResp
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return nil, fmt.Errorf("decode oauth response: %w", err)
	}
	if !ar.OK {
		return nil, fmt.Errorf("oauth.v2.access error: %s", ar.Error)
	}

	// Prefer the user-level token if user scopes were granted; otherwise
	// fall back to the bot-level token.
	access := ar.AuthedUser.AccessToken
	refresh := ar.AuthedUser.RefreshToken
	expires := ar.AuthedUser.ExpiresIn
	scope := ar.AuthedUser.Scope
	if access == "" {
		access = ar.AccessToken
		refresh = ar.RefreshToken
		expires = ar.ExpiresIn
		scope = ar.Scope
	}

	if access == "" {
		return nil, errors.New("oauth response had no access_token (neither user nor bot)")
	}
	if refresh == "" {
		return nil, errors.New("oauth response had no refresh_token — make sure 'Token Rotation' is enabled in your Slack app config")
	}
	if expires <= 0 {
		return nil, errors.New("oauth response had no expires_in — make sure 'Token Rotation' is enabled in your Slack app config")
	}

	return &credFile{
		Version:      1,
		TeamID:       ar.Team.ID,
		UserID:       ar.AuthedUser.ID,
		AccessToken:  access,
		RefreshToken: refresh,
		ExpiresAt:    time.Now().Add(time.Duration(expires) * time.Second),
		Scope:        scope,
	}, nil
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := readRand(b); err != nil {
		panic(err)
	}
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0xf]
	}
	return string(out)
}

func exitf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}
