package provider

import (
	"context"
	"errors"
	"os"

	"github.com/korotovsky/slack-mcp-server/pkg/limiter"
	"github.com/korotovsky/slack-mcp-server/pkg/rotator"
	"github.com/korotovsky/slack-mcp-server/pkg/rotauth"
	"github.com/slack-go/slack"
	"go.uber.org/zap"
)

// newWithRotatingOAuth constructs an ApiProvider whose Slack client uses an
// access token managed by pkg/rotator. The rotator is started here and runs
// for the process lifetime; on each refresh, it notifies a goroutine that
// rebuilds the underlying *slack.Client and *edge.Client so subsequent API
// calls use the new token.
//
// On terminal refresh failure (invalid_grant), the rotator stops and the
// in-memory access token will eventually expire — at which point Slack will
// start returning auth errors and the operator must re-bootstrap. We log
// loudly when this happens; we do not crash the server.
func newWithRotatingOAuth(transport, clientID, clientSecret, credFile string, logger *zap.Logger) *ApiProvider {
	rot, err := rotator.New(rotator.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		FilePath:     credFile,
		Logger:       logger,
	})
	if err != nil {
		logger.Fatal("Failed to construct token rotator",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}
	// Synchronously refresh if the on-disk token is within RefreshLead of
	// expiry, BEFORE starting the background loop or validating. This avoids
	// racing the goroutine: if the cred file is already expired at startup,
	// validateAuthAndGetTeamID would otherwise hit Slack with the stale token
	// and fatal. ErrInvalidGrant is terminal (re-bootstrap required); transient
	// errors fall through and let validation try the existing in-memory token.
	if err := rot.RefreshIfDue(context.Background()); err != nil {
		if errors.Is(err, rotator.ErrInvalidGrant) {
			logger.Fatal("Refresh token rejected at startup - re-bootstrap required (run slack-mcp-oauth-init)",
				zap.String("context", "console"),
				zap.Error(err),
			)
		}
		logger.Warn("Initial token refresh failed (transient); proceeding with existing token",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	rot.Start(context.Background())

	authProvider := rotauth.New(rot)

	teamID, err := validateAuthAndGetTeamID(authProvider, logger)
	if err != nil {
		logger.Fatal("Authentication failed - check rotating OAuth credentials",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	usersCache := os.Getenv("SLACK_MCP_USERS_CACHE")
	if usersCache == "" {
		usersCache = getCachePathWithTeamID(teamID, "users_cache.json")
	}

	channelsCache := os.Getenv("SLACK_MCP_CHANNELS_CACHE")
	if channelsCache == "" {
		channelsCache = getCachePathWithTeamID(teamID, "channels_cache_v2.json")
	}

	client, err := NewMCPSlackClient(authProvider, logger)
	if err != nil {
		logger.Fatal("Failed to create MCP Slack client",
			zap.String("context", "console"),
			zap.Error(err),
		)
	}

	// Subscribe to rotator updates and rebuild the slack/edge clients on
	// each new token. The rotator has a buffered channel; we treat each
	// receive as "check Snapshot and rebuild," not "this is the new token."
	updates, _ := rot.Subscribe()
	go func() {
		for range updates {
			if err := client.Rebuild(); err != nil {
				logger.Error("rotator: client rebuild failed after token refresh",
					zap.String("context", "console"),
					zap.Error(err),
				)
				continue
			}
			logger.Info("rotator: slack/edge clients rebuilt with rotated token",
				zap.String("context", "console"),
			)
		}
	}()

	ap := &ApiProvider{
		transport: transport,
		client:    client,
		logger:    logger,

		rateLimiter:        limiter.Tier2.Limiter(),
		cacheTTL:           getCacheTTL(),
		minRefreshInterval: getMinRefreshInterval(),

		usersCachePath:    usersCache,
		channelsCachePath: channelsCache,
	}
	ap.usersSnapshot.Store(&UsersCache{
		Users:    make(map[string]slack.User),
		UsersInv: make(map[string]string),
	})
	ap.channelsSnapshot.Store(&ChannelsCache{
		Channels:    make(map[string]Channel),
		ChannelsInv: make(map[string]string),
	})
	return ap
}
