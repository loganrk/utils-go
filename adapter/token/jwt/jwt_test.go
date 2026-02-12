package jwt

import (
	"testing"
	"time"
)

func TestNewValidation(t *testing.T) {
	t.Run("unsupported method", func(t *testing.T) {
		_, err := New("ES256", nil, "", "")
		if err == nil {
			t.Fatal("expected error for unsupported method")
		}
	})

	t.Run("missing hmac key", func(t *testing.T) {
		_, err := New("HS256", nil, "", "")
		if err == nil {
			t.Fatal("expected error for missing hmac key")
		}
	})
}

func TestAccessAndRefreshTokenRoundTrip(t *testing.T) {
	tok, err := New("HS256", []byte("secret-key"), "", "")
	if err != nil {
		t.Fatalf("unexpected error creating token adapter: %v", err)
	}

	expiry := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)

	accessToken, err := tok.CreateAccessToken("usi-123", "jdoe", "Jane Doe", expiry)
	if err != nil {
		t.Fatalf("unexpected error creating access token: %v", err)
	}

	usi, accessExp, err := tok.GetAccessTokenData(accessToken)
	if err != nil {
		t.Fatalf("unexpected error reading access token: %v", err)
	}
	if usi != "usi-123" {
		t.Fatalf("unexpected usi: %s", usi)
	}
	if !accessExp.Equal(expiry) {
		t.Fatalf("unexpected access expiry: got %v want %v", accessExp, expiry)
	}

	refreshToken, err := tok.CreateRefreshToken("usi-123", expiry)
	if err != nil {
		t.Fatalf("unexpected error creating refresh token: %v", err)
	}

	refreshUSI, refreshExp, err := tok.GetRefreshTokenData(refreshToken)
	if err != nil {
		t.Fatalf("unexpected error reading refresh token: %v", err)
	}
	if refreshUSI != "usi-123" {
		t.Fatalf("unexpected refresh usi: %s", refreshUSI)
	}
	if !refreshExp.Equal(expiry) {
		t.Fatalf("unexpected refresh expiry: got %v want %v", refreshExp, expiry)
	}
}

func TestTokenTypeMismatch(t *testing.T) {
	tok, err := New("HS256", []byte("secret-key"), "", "")
	if err != nil {
		t.Fatalf("unexpected error creating token adapter: %v", err)
	}

	refreshToken, err := tok.CreateRefreshToken("usi-123", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected error creating refresh token: %v", err)
	}

	_, _, err = tok.GetAccessTokenData(refreshToken)
	if err == nil {
		t.Fatal("expected token type mismatch error")
	}
}
