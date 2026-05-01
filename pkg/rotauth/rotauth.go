// Package rotauth wires the rotator into slackdump's auth.Provider interface
// so the rest of slack-mcp-server can use a rotating xoxp token via the
// existing auth abstraction.
package rotauth

import (
	"context"
	"net/http"

	"github.com/korotovsky/slack-mcp-server/pkg/rotator"
	"github.com/rusq/slack"
)

// Provider implements github.com/rusq/slackdump/v3/auth.Provider on top of a
// running *rotator.Rotator. SlackToken() returns the current rotated token;
// callers that cache the result (e.g. *slack.Client) must subscribe to the
// rotator and rebuild themselves when the token changes.
type Provider struct {
	r *rotator.Rotator
}

func New(r *rotator.Rotator) *Provider {
	return &Provider{r: r}
}

func (p *Provider) SlackToken() string {
	return p.r.Snapshot().AccessToken
}

func (p *Provider) Cookies() []*http.Cookie {
	return nil
}

func (p *Provider) Validate() error {
	if p.r.Snapshot().AccessToken == "" {
		return errNoToken
	}
	return nil
}

func (p *Provider) Test(_ context.Context) (*slack.AuthTestResponse, error) {
	// AuthTest is performed inside provider.NewMCPSlackClient via the slack
	// client; this provider does not need to duplicate it. Return a stub
	// minimal response from the snapshot so callers that rely on Test for
	// basic identity have something to work with.
	s := p.r.Snapshot()
	return &slack.AuthTestResponse{
		TeamID: s.TeamID,
		UserID: s.UserID,
	}, nil
}

// HTTPClient returns a default *http.Client. The slack-mcp-server's edge
// constructor calls this and then immediately overrides the result via
// OptionHTTPClient, so what we return here is effectively a placeholder —
// but it must not error.
func (p *Provider) HTTPClient() (*http.Client, error) {
	return &http.Client{}, nil
}
