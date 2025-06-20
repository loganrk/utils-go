package oAuth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/idtoken"
)

type oauthAdapter struct {
	httpClient *http.Client
}

func NewOAuthAdapter() *oauthAdapter {
	return &oauthAdapter{
		httpClient: http.DefaultClient,
	}
}

type appleClaims struct {
	Email string `json:"email"`
}

func (a *oauthAdapter) VerifyToken(ctx context.Context, provider string, token string) (string, string, error) {
	switch strings.ToLower(provider) {
	case "google":
		return a.verifyGoogle(ctx, token)
	default:
		return "", "", fmt.Errorf("unsupported provider: %s", provider)
	}
}

func (a *oauthAdapter) verifyGoogle(ctx context.Context, token string) (string, string, error) {
	payload, err := idtoken.Validate(ctx, token, "")
	if err != nil {
		return "", "", fmt.Errorf("google token validation failed: %w", err)
	}

	email, _ := payload.Claims["email"].(string)
	givenName, _ := payload.Claims["given_name"].(string)
	familyName, _ := payload.Claims["family_name"].(string)

	return email, givenName + "" + familyName, nil
}
