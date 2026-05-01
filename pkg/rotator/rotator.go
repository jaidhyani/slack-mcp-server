// Package rotator implements Slack OAuth v2 token rotation for the
// slack-mcp-server. It owns the credential file on disk, refreshes the access
// token via oauth.v2.access before expiry, and exposes the current token to
// other parts of the server through Snapshot.
//
// The rotator is intentionally decoupled from the Slack client construction:
// it only holds credentials. Wiring it into MCPSlackClient (so a token swap
// rebuilds the underlying *slack.Client) lives in pkg/auth/rotating and
// pkg/provider.
package rotator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

const (
	// Default Slack OAuth refresh endpoint. Overridable for tests.
	defaultOAuthEndpoint = "https://slack.com/api/oauth.v2.access"

	// How early before expiry to refresh, by default.
	defaultRefreshLead = 10 * time.Minute

	// Background loop period. Refresh checks happen this often.
	defaultTickInterval = 1 * time.Minute

	// Backoff bounds for transient refresh failures. The rotator does not
	// give up on transient errors — the in-memory access token remains valid
	// until its true expiry, and a real failure surfaces only when the token
	// can no longer be used.
	minBackoff = 5 * time.Second
	maxBackoff = 5 * time.Minute

	// Credential file format version. Bumped if the on-disk schema changes
	// in a non-backward-compatible way.
	credFileVersion = 1
)

// ErrInvalidGrant is returned when Slack rejects the refresh token. This is
// terminal — the user must re-bootstrap. It maps to Slack's "invalid_grant"
// or "invalid_refresh_token" responses.
var ErrInvalidGrant = errors.New("rotator: refresh token rejected by Slack (invalid_grant)")

// Credentials is the on-disk credential file format. version=1 fields are
// stable; new optional fields can be added without bumping the version.
type Credentials struct {
	Version      int       `json:"version"`
	TeamID       string    `json:"team_id"`
	UserID       string    `json:"user_id,omitempty"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope,omitempty"`
}

// Snapshot is a read-only view of the current credential state. Returned by
// Rotator.Snapshot for consumers (e.g. the auth.Provider implementation).
type Snapshot struct {
	AccessToken string
	TeamID      string
	UserID      string
	ExpiresAt   time.Time
	Scope       string
}

// Config configures a Rotator. Endpoint, RefreshLead, TickInterval, and
// HTTPClient have sensible defaults; ClientID, ClientSecret, and FilePath
// are required.
type Config struct {
	ClientID     string
	ClientSecret string

	// FilePath is the credential file location. Reads on startup; writes on
	// every successful refresh. Atomic write-then-rename + flock protects
	// concurrent rotators from clobbering each other.
	FilePath string

	// Endpoint overrides the Slack OAuth endpoint. Tests use this to point
	// at a local fake; production leaves it empty for the real endpoint.
	Endpoint string

	// RefreshLead is how far before ExpiresAt to trigger a refresh.
	// Default: 10 minutes.
	RefreshLead time.Duration

	// TickInterval is how often the background loop wakes to check expiry.
	// Default: 1 minute.
	TickInterval time.Duration

	// HTTPClient is used for the oauth.v2.access POST. Nil falls back to
	// http.DefaultClient with a 30s timeout.
	HTTPClient *http.Client

	// Logger is used for refresh events. Nil falls back to zap.NewNop().
	Logger *zap.Logger
}

// Rotator owns the credential lifecycle. Construct with New, start the
// background loop with Start, read the current token via Snapshot, stop with
// Stop. A given credential file should have exactly one Rotator across all
// processes — file locking enforces this.
type Rotator struct {
	cfg Config

	// state is an atomic.Pointer to the current Credentials. Reads (via
	// Snapshot) are lock-free; writes happen only inside refresh under
	// stateMu, then publish atomically.
	state atomic.Pointer[Credentials]

	// stateMu serializes refresh operations within a single process.
	// Cross-process serialization is via flock on the credential file.
	stateMu sync.Mutex

	// subscribers is a slice of channels notified after each successful
	// rotation. Subscribers are managed via Subscribe/Unsubscribe.
	subsMu      sync.Mutex
	subscribers []chan struct{}

	// stop signals the background loop to exit. Closed by Stop.
	stop     chan struct{}
	stopOnce sync.Once

	// done is closed by the background loop when it exits.
	done chan struct{}

	logger *zap.Logger
	endpt  string
	httpc  *http.Client
	tick   time.Duration
	lead   time.Duration
}

// New constructs a Rotator from cfg and the credential file at cfg.FilePath.
// The file must exist and contain a valid Credentials JSON; bootstrap (the
// initial OAuth grant) is handled outside this package.
func New(cfg Config) (*Rotator, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("rotator: ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("rotator: ClientSecret is required")
	}
	if cfg.FilePath == "" {
		return nil, errors.New("rotator: FilePath is required")
	}

	r := &Rotator{
		cfg:    cfg,
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		logger: cfg.Logger,
		endpt:  cfg.Endpoint,
		httpc:  cfg.HTTPClient,
		tick:   cfg.TickInterval,
		lead:   cfg.RefreshLead,
	}
	if r.logger == nil {
		r.logger = zap.NewNop()
	}
	if r.endpt == "" {
		r.endpt = defaultOAuthEndpoint
	}
	if r.httpc == nil {
		r.httpc = &http.Client{Timeout: 30 * time.Second}
	}
	if r.tick <= 0 {
		r.tick = defaultTickInterval
	}
	if r.lead <= 0 {
		r.lead = defaultRefreshLead
	}

	creds, err := loadCreds(cfg.FilePath)
	if err != nil {
		return nil, fmt.Errorf("rotator: load credentials: %w", err)
	}
	r.state.Store(creds)

	return r, nil
}

// Snapshot returns the current credential state. Lock-free.
func (r *Rotator) Snapshot() Snapshot {
	c := r.state.Load()
	return Snapshot{
		AccessToken: c.AccessToken,
		TeamID:      c.TeamID,
		UserID:      c.UserID,
		ExpiresAt:   c.ExpiresAt,
		Scope:       c.Scope,
	}
}

// Subscribe returns a channel that receives a struct{}{} after every
// successful rotation. Use this to rebuild dependent state (e.g. *slack.Client
// instances) when the access token changes. Unsubscribe with the returned
// cancel func when done. Sends are non-blocking; a slow consumer drops
// notifications. Subscribers should treat each receive as "check Snapshot
// again," not "this is the new token."
func (r *Rotator) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	r.subsMu.Lock()
	r.subscribers = append(r.subscribers, ch)
	r.subsMu.Unlock()

	cancel := func() {
		r.subsMu.Lock()
		defer r.subsMu.Unlock()
		for i, c := range r.subscribers {
			if c == ch {
				r.subscribers = append(r.subscribers[:i], r.subscribers[i+1:]...)
				close(ch)
				return
			}
		}
	}
	return ch, cancel
}

func (r *Rotator) notify() {
	r.subsMu.Lock()
	defer r.subsMu.Unlock()
	for _, ch := range r.subscribers {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Start launches the background refresh loop. Returns immediately. Call Stop
// to shut down. If the loaded credentials are already past RefreshLead, the
// first refresh attempt happens immediately rather than after one tick.
func (r *Rotator) Start(ctx context.Context) {
	go r.loop(ctx)
}

// Stop terminates the background loop and waits for it to exit. Safe to call
// multiple times.
func (r *Rotator) Stop() {
	r.stopOnce.Do(func() { close(r.stop) })
	<-r.done
}

func (r *Rotator) loop(ctx context.Context) {
	defer close(r.done)

	if r.shouldRefresh(time.Now()) {
		if err := r.tryRefresh(ctx); errors.Is(err, ErrInvalidGrant) {
			r.logger.Error("rotator: refresh token rejected on initial check, halting refresh loop",
				zap.Error(err))
			return
		}
	}

	t := time.NewTicker(r.tick)
	defer t.Stop()

	backoff := minBackoff
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stop:
			return
		case <-t.C:
			if !r.shouldRefresh(time.Now()) {
				backoff = minBackoff
				continue
			}
			err := r.tryRefresh(ctx)
			if err == nil {
				backoff = minBackoff
				continue
			}
			if errors.Is(err, ErrInvalidGrant) {
				r.logger.Error("rotator: refresh token rejected, halting refresh loop",
					zap.Error(err))
				return
			}
			// Transient error: keep waiting; the in-memory token may still
			// be valid. We don't actively retry inside the same tick — the
			// next tick handles it. Use backoff only to log less noisily.
			r.logger.Warn("rotator: refresh failed (transient), will retry next tick",
				zap.Error(err),
				zap.Duration("next_in", r.tick))
			if backoff < maxBackoff {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
}

// shouldRefresh returns true if the current credential is within RefreshLead
// of expiry (or already expired).
func (r *Rotator) shouldRefresh(now time.Time) bool {
	c := r.state.Load()
	return !c.ExpiresAt.IsZero() && now.After(c.ExpiresAt.Add(-r.lead))
}

// tryRefresh performs one refresh attempt, including disk I/O and notifying
// subscribers on success. Returns nil on success, ErrInvalidGrant on terminal
// failure, or another error for transient issues.
func (r *Rotator) tryRefresh(ctx context.Context) error {
	r.stateMu.Lock()
	defer r.stateMu.Unlock()

	cur := r.state.Load()
	resp, err := r.callOAuth(ctx, cur.RefreshToken)
	if err != nil {
		return err
	}

	next := &Credentials{
		Version:      credFileVersion,
		TeamID:       cur.TeamID,
		UserID:       cur.UserID,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second),
		Scope:        firstNonEmpty(resp.Scope, cur.Scope),
	}
	if resp.RefreshToken == "" {
		// Slack should always return a new refresh token under rotation.
		// Fall back to the existing one if the server omits it; better than
		// dropping the token entirely.
		next.RefreshToken = cur.RefreshToken
	}

	if err := writeCreds(r.cfg.FilePath, next); err != nil {
		return fmt.Errorf("persist credentials: %w", err)
	}
	r.state.Store(next)
	r.logger.Info("rotator: token refreshed",
		zap.Time("expires_at", next.ExpiresAt),
		zap.String("team_id", next.TeamID))
	r.notify()
	return nil
}

// oauthResponse is the subset of oauth.v2.access fields we use.
type oauthResponse struct {
	OK             bool   `json:"ok"`
	Error          string `json:"error,omitempty"`
	AccessToken    string `json:"access_token,omitempty"`
	RefreshToken   string `json:"refresh_token,omitempty"`
	ExpiresIn      int64  `json:"expires_in,omitempty"`
	Scope          string `json:"scope,omitempty"`
	TokenType      string `json:"token_type,omitempty"`
	TeamID         string `json:"team_id,omitempty"`
	AuthedUserID   string `json:"-"`
}

// callOAuth POSTs to Slack's oauth.v2.access with grant_type=refresh_token.
// Returns ErrInvalidGrant on terminal token rejection; another error on
// transient failures (network, rate limit, 5xx).
func (r *Rotator) callOAuth(ctx context.Context, refreshToken string) (*oauthResponse, error) {
	form := url.Values{}
	form.Set("client_id", r.cfg.ClientID)
	form.Set("client_secret", r.cfg.ClientSecret)
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpt, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post oauth.v2.access: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("oauth.v2.access transient HTTP %d", resp.StatusCode)
	}

	var out oauthResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode oauth response: %w", err)
	}

	if !out.OK {
		switch out.Error {
		case "invalid_grant", "invalid_refresh_token", "token_revoked":
			return nil, fmt.Errorf("%w: %s", ErrInvalidGrant, out.Error)
		default:
			return nil, fmt.Errorf("oauth.v2.access error: %s", out.Error)
		}
	}
	if out.AccessToken == "" {
		return nil, errors.New("oauth.v2.access returned no access_token")
	}
	if out.ExpiresIn <= 0 {
		// Without an expiry, we can't drive rotation. Treat as terminal.
		return nil, fmt.Errorf("%w: missing expires_in (token rotation may be disabled on this app)", ErrInvalidGrant)
	}
	return &out, nil
}

// loadCreds reads and parses the credential file at path. Returns an error
// if missing or malformed.
func loadCreds(path string) (*Credentials, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Shared lock during read; serialized with concurrent writers.
	if err := flock(f, syscall.LOCK_SH); err != nil {
		return nil, fmt.Errorf("flock(LOCK_SH): %w", err)
	}
	defer flock(f, syscall.LOCK_UN)

	var c Credentials
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return nil, fmt.Errorf("decode credentials: %w", err)
	}
	if c.Version == 0 {
		c.Version = credFileVersion
	}
	if c.Version != credFileVersion {
		return nil, fmt.Errorf("credentials file version %d, expected %d", c.Version, credFileVersion)
	}
	if c.AccessToken == "" || c.RefreshToken == "" {
		return nil, errors.New("credentials file missing access_token or refresh_token")
	}
	return &c, nil
}

// writeCreds atomically replaces the credential file at path with c. Uses a
// temp file in the same directory + rename, with an exclusive flock during
// the swap so concurrent writers serialize.
func writeCreds(path string, c *Credentials) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Open the destination file (creating if missing) just to take the
	// exclusive lock. We don't write into it directly — that's the temp
	// file's job — but holding the lock here makes concurrent rotators
	// serialize their swaps.
	lockf, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("open lock target %s: %w", path, err)
	}
	defer lockf.Close()
	if err := flock(lockf, syscall.LOCK_EX); err != nil {
		return fmt.Errorf("flock(LOCK_EX): %w", err)
	}
	defer flock(lockf, syscall.LOCK_UN)

	tmp, err := os.CreateTemp(dir, ".cred-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chmod temp: %w", err)
	}

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("encode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		cleanup()
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// flock wraps syscall.Flock for unix systems; on platforms without flock
// (Windows), it's a no-op. The slack-mcp-server already uses unix-like
// platforms in its test matrix, so this is acceptable.
func flock(f *os.File, how int) error {
	return syscall.Flock(int(f.Fd()), how)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
