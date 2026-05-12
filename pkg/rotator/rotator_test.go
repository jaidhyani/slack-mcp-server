package rotator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// fakeOAuth simulates Slack's oauth.v2.access endpoint for tests.
// Tracks call count, can be configured to return specific responses or
// errors, and rotates the refresh token on each successful call (mirroring
// real Slack behavior).
type fakeOAuth struct {
	calls atomic.Int32

	// Response controls. mu-less because tests configure these once before
	// starting the rotator and read them after Stop.
	wantClientID     string
	wantClientSecret string

	// nextResponses is a queue of responses; if empty, default success.
	nextResponses []fakeResp

	// counter for unique tokens emitted
	tokenCounter atomic.Int32
}

type fakeResp struct {
	httpStatus int
	body       map[string]any
}

func (f *fakeOAuth) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		_ = r.ParseForm()

		if f.wantClientID != "" && r.PostFormValue("client_id") != f.wantClientID {
			http.Error(w, "wrong client_id", http.StatusBadRequest)
			return
		}
		if f.wantClientSecret != "" && r.PostFormValue("client_secret") != f.wantClientSecret {
			http.Error(w, "wrong client_secret", http.StatusBadRequest)
			return
		}
		if r.PostFormValue("grant_type") != "refresh_token" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		if r.PostFormValue("refresh_token") == "" {
			http.Error(w, "missing refresh_token", http.StatusBadRequest)
			return
		}

		var resp fakeResp
		if len(f.nextResponses) > 0 {
			resp = f.nextResponses[0]
			f.nextResponses = f.nextResponses[1:]
		} else {
			n := f.tokenCounter.Add(1)
			resp = fakeResp{
				httpStatus: 200,
				body: map[string]any{
					"ok":            true,
					"access_token":  "xoxe.xoxp-rotated-" + itoa(n),
					"refresh_token": "xoxe-refresh-" + itoa(n),
					"expires_in":    3600,
					"scope":         "search:read,channels:history",
				},
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if resp.httpStatus == 0 {
			resp.httpStatus = 200
		}
		w.WriteHeader(resp.httpStatus)
		if resp.body != nil {
			_ = json.NewEncoder(w).Encode(resp.body)
		}
	})
}

func itoa(n int32) string {
	return string('0' + rune(n%10))
}

// writeInitialCreds writes a starting credential file for tests.
func writeInitialCreds(t *testing.T, dir string, expiresAt time.Time) string {
	t.Helper()
	path := filepath.Join(dir, "creds.json")
	c := &Credentials{
		Version:      1,
		TeamID:       "T_TEST",
		UserID:       "U_TEST",
		AccessToken:  "xoxe.xoxp-initial",
		RefreshToken: "xoxe-refresh-initial",
		ExpiresAt:    expiresAt,
		Scope:        "search:read",
	}
	if err := writeCreds(path, c); err != nil {
		t.Fatalf("writeInitialCreds: %v", err)
	}
	return path
}

func TestNew_LoadsCredentialsFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := writeInitialCreds(t, dir, time.Now().Add(time.Hour))

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	snap := r.Snapshot()
	if snap.AccessToken != "xoxe.xoxp-initial" {
		t.Errorf("AccessToken = %q, want xoxe.xoxp-initial", snap.AccessToken)
	}
	if snap.TeamID != "T_TEST" {
		t.Errorf("TeamID = %q, want T_TEST", snap.TeamID)
	}
}

func TestNew_RejectsMissingClientID(t *testing.T) {
	dir := t.TempDir()
	path := writeInitialCreds(t, dir, time.Now().Add(time.Hour))
	_, err := New(Config{ClientSecret: "csec", FilePath: path})
	if err == nil {
		t.Fatal("expected error for missing ClientID")
	}
}

func TestNew_RejectsMalformedCredFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
	})
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestRefresh_HappyPath(t *testing.T) {
	dir := t.TempDir()
	// expires very soon → should refresh on the first tick
	path := writeInitialCreds(t, dir, time.Now().Add(1*time.Second))

	fake := &fakeOAuth{wantClientID: "cid", wantClientSecret: "csec"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
		Endpoint:     srv.URL,
		RefreshLead:  10 * time.Second, // anything within 10s triggers refresh
		TickInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.Start(ctx)
	defer r.Stop()

	// Wait for at least one refresh.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fake.calls.Load() > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if fake.calls.Load() == 0 {
		t.Fatal("expected at least one refresh call")
	}

	snap := r.Snapshot()
	if snap.AccessToken == "xoxe.xoxp-initial" {
		t.Errorf("AccessToken not rotated: still %q", snap.AccessToken)
	}
	if snap.ExpiresAt.Before(time.Now().Add(30 * time.Minute)) {
		t.Errorf("ExpiresAt = %v, expected ~1h from now", snap.ExpiresAt)
	}

	// File on disk should reflect the new state.
	on, err := loadCreds(path)
	if err != nil {
		t.Fatalf("loadCreds: %v", err)
	}
	if on.AccessToken != snap.AccessToken {
		t.Errorf("disk AccessToken = %q, in-memory = %q", on.AccessToken, snap.AccessToken)
	}
}

func TestRefresh_DoesNotRefreshIfNotDue(t *testing.T) {
	dir := t.TempDir()
	// expires far in the future → no refresh
	path := writeInitialCreds(t, dir, time.Now().Add(24*time.Hour))

	fake := &fakeOAuth{wantClientID: "cid", wantClientSecret: "csec"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
		Endpoint:     srv.URL,
		RefreshLead:  1 * time.Minute,
		TickInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r.Start(context.Background())
	defer r.Stop()
	time.Sleep(150 * time.Millisecond)

	if got := fake.calls.Load(); got != 0 {
		t.Errorf("expected 0 refresh calls, got %d", got)
	}
}

func TestRefresh_InvalidGrantHaltsLoop(t *testing.T) {
	dir := t.TempDir()
	path := writeInitialCreds(t, dir, time.Now().Add(1*time.Second))

	fake := &fakeOAuth{
		wantClientID:     "cid",
		wantClientSecret: "csec",
		nextResponses: []fakeResp{
			{httpStatus: 200, body: map[string]any{"ok": false, "error": "invalid_grant"}},
		},
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
		Endpoint:     srv.URL,
		RefreshLead:  10 * time.Second,
		TickInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r.Start(context.Background())
	defer r.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fake.calls.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Wait a bit longer to see if the loop keeps hammering. It shouldn't.
	time.Sleep(200 * time.Millisecond)
	first := fake.calls.Load()
	time.Sleep(200 * time.Millisecond)
	second := fake.calls.Load()

	if second != first {
		t.Errorf("loop kept calling after invalid_grant: first=%d second=%d", first, second)
	}

	// Snapshot should still hold the original token (we never wrote a new one).
	snap := r.Snapshot()
	if snap.AccessToken != "xoxe.xoxp-initial" {
		t.Errorf("AccessToken should be unchanged after invalid_grant, got %q", snap.AccessToken)
	}
}

func TestRefresh_TransientErrorRetries(t *testing.T) {
	dir := t.TempDir()
	path := writeInitialCreds(t, dir, time.Now().Add(1*time.Second))

	fake := &fakeOAuth{
		wantClientID:     "cid",
		wantClientSecret: "csec",
		nextResponses: []fakeResp{
			{httpStatus: 503, body: nil},
			// next call falls through to default success
		},
	}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
		Endpoint:     srv.URL,
		RefreshLead:  10 * time.Second,
		TickInterval: 30 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	r.Start(context.Background())
	defer r.Stop()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.Snapshot().AccessToken != "xoxe.xoxp-initial" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if r.Snapshot().AccessToken == "xoxe.xoxp-initial" {
		t.Errorf("rotator did not recover from transient error, still on initial token")
	}
	if fake.calls.Load() < 2 {
		t.Errorf("expected at least 2 calls (one fail, one success), got %d", fake.calls.Load())
	}
}

func TestRefreshIfDue_RefreshesSynchronouslyWhenExpired(t *testing.T) {
	dir := t.TempDir()
	// expires in the past → should refresh synchronously
	path := writeInitialCreds(t, dir, time.Now().Add(-1*time.Hour))

	fake := &fakeOAuth{wantClientID: "cid", wantClientSecret: "csec"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
		Endpoint:     srv.URL,
		RefreshLead:  10 * time.Minute,
		TickInterval: 1 * time.Hour, // ticker should never fire during test
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Do NOT call Start — RefreshIfDue must work synchronously without the
	// background loop, since the whole point is to beat the goroutine.
	if err := r.RefreshIfDue(context.Background()); err != nil {
		t.Fatalf("RefreshIfDue: %v", err)
	}
	if fake.calls.Load() != 1 {
		t.Errorf("expected 1 refresh call, got %d", fake.calls.Load())
	}
	if r.Snapshot().AccessToken == "xoxe.xoxp-initial" {
		t.Error("RefreshIfDue did not rotate the in-memory access token")
	}
}

func TestRefreshIfDue_NoOpWhenNotDue(t *testing.T) {
	dir := t.TempDir()
	path := writeInitialCreds(t, dir, time.Now().Add(24*time.Hour))

	fake := &fakeOAuth{wantClientID: "cid", wantClientSecret: "csec"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
		Endpoint:     srv.URL,
		RefreshLead:  1 * time.Minute,
		TickInterval: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.RefreshIfDue(context.Background()); err != nil {
		t.Fatalf("RefreshIfDue: %v", err)
	}
	if fake.calls.Load() != 0 {
		t.Errorf("expected 0 refresh calls (not due), got %d", fake.calls.Load())
	}
}

func TestRefreshNow_AlwaysRefreshes(t *testing.T) {
	dir := t.TempDir()
	// not due → RefreshIfDue would skip, but RefreshNow must call anyway
	path := writeInitialCreds(t, dir, time.Now().Add(24*time.Hour))

	fake := &fakeOAuth{wantClientID: "cid", wantClientSecret: "csec"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
		Endpoint:     srv.URL,
		RefreshLead:  1 * time.Minute,
		TickInterval: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := r.RefreshNow(context.Background()); err != nil {
		t.Fatalf("RefreshNow: %v", err)
	}
	if fake.calls.Load() != 1 {
		t.Errorf("expected 1 refresh call, got %d", fake.calls.Load())
	}
}

func TestSubscribe_NotifiesOnRotation(t *testing.T) {
	dir := t.TempDir()
	path := writeInitialCreds(t, dir, time.Now().Add(1*time.Second))

	fake := &fakeOAuth{wantClientID: "cid", wantClientSecret: "csec"}
	srv := httptest.NewServer(fake.handler())
	defer srv.Close()

	r, err := New(Config{
		ClientID:     "cid",
		ClientSecret: "csec",
		FilePath:     path,
		Endpoint:     srv.URL,
		RefreshLead:  10 * time.Second,
		TickInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ch, cancel := r.Subscribe()
	defer cancel()

	r.Start(context.Background())
	defer r.Stop()

	select {
	case <-ch:
		// good
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber never notified")
	}
}

func TestPersistence_AtomicAcrossProcesses(t *testing.T) {
	// Verify the disk write is atomic: the file always parses, even
	// concurrent with reads. Indirect test — we just write+read in a tight
	// loop and confirm no parse errors.
	dir := t.TempDir()
	path := writeInitialCreds(t, dir, time.Now().Add(time.Hour))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 50; i++ {
			c := &Credentials{
				Version:      1,
				TeamID:       "T_TEST",
				AccessToken:  "xoxe.xoxp-write-" + itoa(int32(i)),
				RefreshToken: "xoxe-refresh-write",
				ExpiresAt:    time.Now().Add(time.Hour),
			}
			if err := writeCreds(path, c); err != nil {
				t.Errorf("writeCreds[%d]: %v", i, err)
				return
			}
		}
	}()

	for i := 0; i < 100; i++ {
		_, err := loadCreds(path)
		if err != nil {
			t.Errorf("loadCreds[%d]: %v", i, err)
			return
		}
		time.Sleep(time.Millisecond)
	}
	<-done
}
