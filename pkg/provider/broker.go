package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// brokerCredentialResponse mirrors the JSON shape returned by
// ohanalabs-ai/mcp-oauth-broker's GET /internal/credentials/latest (see
// src/internal/routes.ts in that repo). providerData is intentionally
// map[string]any -- it's opaque per-provider data on the broker side too
// (see that repo's src/credentials/record.ts), so this side only reaches
// into the one field it actually needs (accessToken).
type brokerCredentialResponse struct {
	Provider         string         `json:"provider"`
	Subject          string         `json:"subject"`
	ProviderData     map[string]any `json:"providerData"`
	ExpiresAt        int64          `json:"expiresAt"`
	LastVerified     int64          `json:"lastVerifiedAt"`
	Error            string         `json:"error"`
	ErrorDescription string         `json:"error_description"`
}

// FetchLatestBrokerCredential fetches the current Slack access token from a
// running mcp-oauth-broker instance, if MCP_OAUTH_BROKER_URL is configured.
// Returns ("", nil) -- not an error -- when the env var is unset, so callers
// can treat "broker not configured" and "broker fetch skipped" identically
// and fall through to the static SLACK_MCP_XOXP_TOKEN env var unchanged.
//
// This is a startup-time fetch, not a live subscription: it is called once
// from New() before constructing the Slack client. A token refreshed on the
// broker afterward does not take effect here without restarting this
// process -- see docs/03-configuration-and-usage.md's "OAuth broker
// integration" section for why (ApiProvider.client is read directly by many
// call sites; making it hot-swappable is a separate, larger change tracked
// there rather than folded into this one).
func FetchLatestBrokerCredential(logger *zap.Logger) (string, error) {
	brokerURL := os.Getenv("MCP_OAUTH_BROKER_URL")
	if brokerURL == "" {
		return "", nil
	}

	apiKey := os.Getenv("MCP_OAUTH_BROKER_INTERNAL_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("MCP_OAUTH_BROKER_URL is set but MCP_OAUTH_BROKER_INTERNAL_API_KEY is not -- both are required together")
	}

	providerID := os.Getenv("MCP_OAUTH_BROKER_PROVIDER")
	if providerID == "" {
		providerID = "slack"
	}

	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	url := fmt.Sprintf("%s/internal/credentials/latest?provider=%s", brokerURL, providerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to build broker credential request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to reach mcp-oauth-broker at %s: %w", brokerURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read mcp-oauth-broker response body: %w", err)
	}

	var parsed brokerCredentialResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("failed to parse mcp-oauth-broker response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		desc := parsed.ErrorDescription
		if desc == "" {
			desc = parsed.Error
		}
		return "", fmt.Errorf("mcp-oauth-broker returned %d: %s", resp.StatusCode, desc)
	}

	accessToken, _ := parsed.ProviderData["accessToken"].(string)
	if accessToken == "" {
		return "", fmt.Errorf("mcp-oauth-broker response is missing providerData.accessToken")
	}

	logger.Info("Fetched Slack credential from mcp-oauth-broker",
		zap.String("context", "console"),
		zap.String("broker_url", brokerURL),
		zap.String("provider", providerID),
		zap.String("subject", parsed.Subject),
	)

	return accessToken, nil
}
