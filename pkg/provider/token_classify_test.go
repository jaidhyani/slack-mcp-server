package provider

import "testing"

// TestClassifyToken locks in the prefix recognition for both unrotated
// (xoxp-/xoxb-) and rotated (xoxe.xoxp-/xoxe.xoxb-) Slack OAuth token
// variants. Adding the xoxe.* coverage here was the fix for an end-to-end
// failure where rotated user tokens were misclassified as session-cookie
// tokens, sending users_search through the edge API and returning
// invalid_auth.
func TestClassifyToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		oauth    bool
		bot      bool
	}{
		{"unrotated user", "xoxp-1234-5678", true, false},
		{"unrotated bot", "xoxb-1234-5678", true, true},
		{"rotated user", "xoxe.xoxp-1-rotated-1234", true, false},
		{"rotated bot", "xoxe.xoxb-1-rotated-1234", true, true},
		{"browser session token", "xoxc-1234-cookie-style", false, false},
		{"empty", "", false, false},
		{"unrelated string", "hello", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOAuth, gotBot := classifyToken(tt.token)
			if gotOAuth != tt.oauth {
				t.Errorf("classifyToken(%q) oauth = %v, want %v", tt.token, gotOAuth, tt.oauth)
			}
			if gotBot != tt.bot {
				t.Errorf("classifyToken(%q) bot = %v, want %v", tt.token, gotBot, tt.bot)
			}
		})
	}
}
