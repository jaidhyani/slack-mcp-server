package main

// End-to-end tests for rotating OAuth across processes: the real server and
// keepalive binaries, sharing one credential file, against a fake Slack that
// retires a token pair whenever it hands out the next one. The binaries reach
// the fake through their own SLACK_MCP_PROXY and SLACK_MCP_SERVER_CA settings.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	fakeClientID     = "fake-client-id"
	fakeClientSecret = "fake-client-secret"
)

// fakeSlack is Slack under token rotation: only the newest access token
// works, older ones get token_revoked, and a refresh must present the newest
// refresh token.
type fakeSlack struct {
	mu        sync.Mutex
	gen       int
	refreshes int
	// oauthDelay holds each oauth.v2.access call before it is judged, so
	// concurrent refreshes overlap.
	oauthDelay time.Duration
}

func (f *fakeSlack) refreshCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes
}

func accessToken(gen int) string  { return fmt.Sprintf("xoxe.xoxp-fake-access-%d", gen) }
func refreshToken(gen int) string { return fmt.Sprintf("xoxe-1-fake-refresh-%d", gen) }

func (f *fakeSlack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	method := strings.TrimPrefix(r.URL.Path, "/api/")
	reply := func(v map[string]any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}

	if method == "oauth.v2.access" {
		time.Sleep(f.oauthDelay)
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.PostFormValue("client_id") != fakeClientID || r.PostFormValue("client_secret") != fakeClientSecret {
			reply(map[string]any{"ok": false, "error": "invalid_client_id"})
			return
		}
		if r.PostFormValue("refresh_token") != refreshToken(f.gen) {
			reply(map[string]any{"ok": false, "error": "invalid_refresh_token"})
			return
		}
		f.gen++
		f.refreshes++
		reply(map[string]any{"ok": true, "access_token": accessToken(f.gen), "refresh_token": refreshToken(f.gen),
			"expires_in": 43200, "token_type": "user", "team": map[string]any{"id": "TFAKE"}})
		return
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		token = r.PostFormValue("token")
	}
	f.mu.Lock()
	gen := f.gen
	f.mu.Unlock()
	switch {
	case token == accessToken(gen):
	case strings.HasPrefix(token, "xoxe.xoxp-fake-access-"):
		reply(map[string]any{"ok": false, "error": "token_revoked"})
		return
	default:
		reply(map[string]any{"ok": false, "error": "invalid_auth"})
		return
	}
	if method == "auth.test" {
		reply(map[string]any{"ok": true, "url": "https://fake.slack.com/", "team": "Fake", "user": "tester",
			"team_id": "TFAKE", "user_id": "UFAKE"})
		return
	}
	reply(map[string]any{"ok": true, "messages": []any{}, "members": []any{}, "channels": []any{},
		"usergroups": []any{}, "has_more": false, "response_metadata": map[string]any{"next_cursor": ""}})
}

// startFakeSlack serves f behind an HTTPS proxy that terminates every CONNECT
// with a certificate for *.slack.com from a throwaway CA. Returns the proxy
// URL and the CA's PEM file.
func startFakeSlack(t *testing.T, f *fakeSlack) (proxyURL, caFile string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake slack CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "slack.com"},
		DNSNames: []string{"slack.com", "*.slack.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{NextProtos: []string{"http/1.1"},
		Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}

	conns := &chanListener{ch: make(chan net.Conn), done: make(chan struct{})}
	api := &http.Server{Handler: f}
	go api.Serve(conns)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		raw, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		_, _ = io.WriteString(raw, "HTTP/1.1 200 Connection established\r\n\r\n")
		select {
		case conns.ch <- tls.Server(raw, tlsCfg):
		case <-conns.done:
			raw.Close()
		}
	})}
	go proxy.Serve(ln)
	t.Cleanup(func() { proxy.Close(); conns.Close(); api.Close() })
	return "http://" + ln.Addr().String(), caFile
}

type chanListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return &net.TCPAddr{} }

// rig is one test's world: the binaries, the fake, and a credential file at
// the fake's first token pair.
type rig struct {
	t        *testing.T
	bin      string
	credFile string
	env      []string
}

var buildOnce struct {
	sync.Once
	dir string
	err error
}

func newRig(t *testing.T, f *fakeSlack) *rig {
	t.Helper()
	if testing.Short() {
		t.Skip("builds and runs the binaries")
	}
	buildOnce.Do(func() {
		buildOnce.dir, buildOnce.err = os.MkdirTemp("", "slack-mcp-rotation-bin-")
		if buildOnce.err != nil {
			return
		}
		out, err := exec.Command("go", "build", "-o", buildOnce.dir+"/",
			"github.com/korotovsky/slack-mcp-server/cmd/slack-mcp-server",
			"github.com/korotovsky/slack-mcp-server/cmd/slack-mcp-keepalive").CombinedOutput()
		if err != nil {
			buildOnce.err = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if buildOnce.err != nil {
		t.Fatal(buildOnce.err)
	}

	proxyURL, caFile := startFakeSlack(t, f)
	home := t.TempDir()
	credFile := filepath.Join(home, "cred.json")
	creds, _ := json.Marshal(map[string]any{"version": 1, "team_id": "TFAKE", "user_id": "UFAKE",
		"access_token": accessToken(f.gen), "refresh_token": refreshToken(f.gen),
		"expires_at": time.Now().Add(12 * time.Hour).Format(time.RFC3339)})
	if err := os.WriteFile(credFile, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, bin: buildOnce.dir, credFile: credFile, env: []string{
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"SLACK_MCP_OAUTH_CLIENT_ID=" + fakeClientID,
		"SLACK_MCP_OAUTH_CLIENT_SECRET=" + fakeClientSecret,
		"SLACK_MCP_OAUTH_CRED_FILE=" + credFile,
		"SLACK_MCP_PROXY=" + proxyURL,
		"SLACK_MCP_SERVER_CA=" + caFile,
		"SLACK_MCP_USERS_CACHE=" + filepath.Join(home, "users.json"),
		"SLACK_MCP_CHANNELS_CACHE=" + filepath.Join(home, "channels.json"),
	}}
}

// keepalive runs the keepalive binary on the rig's credential file and
// returns its exit code and output.
func (r *rig) keepalive() (int, string) {
	cmd := exec.Command(filepath.Join(r.bin, "slack-mcp-keepalive"),
		"-client-id", fakeClientID, "-client-secret", fakeClientSecret, "-cred-file", r.credFile)
	cmd.Env = r.env
	out, _ := cmd.CombinedOutput()
	return cmd.ProcessState.ExitCode(), string(out)
}

// mcpServer is a running server spoken to over stdio, as Claude Code does.
type mcpServer struct {
	t      *testing.T
	stdin  io.WriteCloser
	lines  chan map[string]any
	nextID int
	stderr *strings.Builder
}

func (r *rig) startServer() *mcpServer {
	r.t.Helper()
	cmd := exec.Command(filepath.Join(r.bin, "slack-mcp-server"), "-t", "stdio")
	cmd.Env = r.env
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	s := &mcpServer{t: r.t, stdin: stdin, lines: make(chan map[string]any, 16), stderr: &strings.Builder{}}
	cmd.Stderr = s.stderr
	if err := cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { stdin.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				s.lines <- m
			}
		}
		close(s.lines)
	}()
	s.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "rotation-test", "version": "0"}})
	s.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return s
}

func (s *mcpServer) send(v map[string]any) {
	b, _ := json.Marshal(v)
	if _, err := s.stdin.Write(append(b, '\n')); err != nil {
		s.t.Fatalf("write to server: %v\nstderr:\n%s", err, s.stderr)
	}
}

func (s *mcpServer) call(method string, params map[string]any) map[string]any {
	s.t.Helper()
	s.nextID++
	id := s.nextID
	s.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	timeout := time.After(30 * time.Second)
	for {
		select {
		case m, ok := <-s.lines:
			if !ok {
				s.t.Fatalf("server exited during %s\nstderr:\n%s", method, s.stderr)
			}
			if got, _ := m["id"].(float64); int(got) == id {
				return m
			}
		case <-timeout:
			s.t.Fatalf("no reply to %s\nstderr:\n%s", method, s.stderr)
		}
	}
}

// history calls conversations_history and fails the test unless it worked.
func (s *mcpServer) history(when string) {
	s.t.Helper()
	m := s.call("tools/call", map[string]any{"name": "conversations_history",
		"arguments": map[string]any{"channel_id": "C0FAKE", "limit": "10"}})
	res, _ := m["result"].(map[string]any)
	if m["error"] != nil || res == nil || res["isError"] == true {
		b, _ := json.Marshal(m)
		s.t.Fatalf("conversations_history %s failed: %s", when, b)
	}
}

// A server that outlives a rotation by another process keeps working: the
// nightly keepalive rotates the shared file under a running session, as it
// did under clai-live's on 11/5.
func TestRotationByAnotherProcess(t *testing.T) {
	f := &fakeSlack{gen: 1}
	r := newRig(t, f)

	long := r.startServer()
	long.history("before the rotation")

	if code, out := r.keepalive(); code != 0 {
		t.Fatalf("keepalive exit %d: %s", code, out)
	}
	long.history("after another process rotated the token")
	r.startServer().history("in a server started after the rotation")

	if n := f.refreshCount(); n != 1 {
		t.Errorf("Slack saw %d refreshes, want 1 (the keepalive's; the servers adopt it)", n)
	}
}

// Two processes refreshing at the same moment: the one that loses the race
// finds the winner's token on disk and adopts it instead of presenting the
// refresh token the winner just spent, which Slack would reject as terminal.
func TestConcurrentRefreshes(t *testing.T) {
	f := &fakeSlack{gen: 1, oauthDelay: 500 * time.Millisecond}
	r := newRig(t, f)

	var wg sync.WaitGroup
	codes, outs := make([]int, 2), make([]string, 2)
	for i := range codes {
		wg.Add(1)
		go func(i int) { defer wg.Done(); codes[i], outs[i] = r.keepalive() }(i)
	}
	wg.Wait()
	for i, code := range codes {
		if code != 0 {
			t.Errorf("keepalive %d exit %d: %s", i, code, outs[i])
		}
	}
	if n := f.refreshCount(); n != 1 {
		t.Errorf("Slack saw %d refreshes, want 1", n)
	}
	r.startServer().history("after the concurrent refreshes")
}
