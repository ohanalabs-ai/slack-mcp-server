package auth

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

// jwksRefreshInterval matches mcp-oauth-broker's own README guidance for
// how often a downstream verifier should refetch its JWKS (the broker
// itself only rotates keys on redeploy, not continuously, so this is a
// cache-freshness bound, not a security-critical cadence).
const jwksRefreshInterval = 10 * time.Minute

var (
	brokerKeyfuncMu  sync.Mutex
	brokerKeyfunc    keyfunc.Keyfunc
	brokerKeyfuncURL string
)

// getBrokerKeyfunc returns a process-wide cached keyfunc.Keyfunc for the
// configured broker JWKS URL, creating (or recreating, if the URL changed)
// it on first use. keyfunc itself handles the actual background
// refresh/caching of the key set -- this wrapper only handles lazy
// initialization and re-initialization if MCP_OAUTH_BROKER_ISSUER changes
// between calls (practically only relevant in tests).
func getBrokerKeyfunc(ctx context.Context, jwksURL string) (keyfunc.Keyfunc, error) {
	brokerKeyfuncMu.Lock()
	defer brokerKeyfuncMu.Unlock()

	if brokerKeyfunc != nil && brokerKeyfuncURL == jwksURL {
		return brokerKeyfunc, nil
	}

	kf, err := keyfunc.NewDefaultCtx(ctx, []string{jwksURL})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", jwksURL, err)
	}

	brokerKeyfunc = kf
	brokerKeyfuncURL = jwksURL
	return kf, nil
}

// validateBrokerJWT verifies presentedToken as an RS256 JWT issued by
// mcp-oauth-broker (see that repo's src/oauth/jwt.ts), checking signature
// (via its published JWKS), expiry, and issuer. Returns (false, nil) -- not
// an error -- when MCP_OAUTH_BROKER_ISSUER is unset, so callers can treat
// "broker auth not configured" and "this token isn't a broker JWT" the same
// way and fall through to the static-bearer-token check unchanged.
func validateBrokerJWT(logger *zap.Logger, presentedToken string) (bool, error) {
	issuer := os.Getenv("MCP_OAUTH_BROKER_ISSUER")
	if issuer == "" {
		return false, nil
	}

	jwksURL := issuer + "/.well-known/jwks.json"

	ctx, cancel := context.WithTimeout(context.Background(), jwksRefreshInterval)
	defer cancel()

	kf, err := getBrokerKeyfunc(ctx, jwksURL)
	if err != nil {
		logger.Warn("Failed to load broker JWKS",
			zap.String("context", "http"),
			zap.String("jwks_url", jwksURL),
			zap.Error(err),
		)
		return false, fmt.Errorf("failed to verify broker JWT: %w", err)
	}

	token, err := jwt.Parse(
		presentedToken,
		kf.Keyfunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		logger.Debug("Broker JWT validation failed",
			zap.String("context", "http"),
			zap.Error(err),
		)
		return false, nil
	}

	if !token.Valid {
		return false, nil
	}

	logger.Debug("Broker JWT validated successfully",
		zap.String("context", "http"),
		zap.String("issuer", issuer),
	)
	return true, nil
}
