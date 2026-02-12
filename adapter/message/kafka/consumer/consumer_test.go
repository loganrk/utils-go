package consumer

import (
	"context"
	"encoding/json"
	"testing"
)

func TestRouteActivation(t *testing.T) {
	called := ""
	c := &consumer{
		activationSmsHandler: func(countryCode, to string, macros map[string]string) error {
			called = "sms"
			return nil
		},
		activationEmailHandler: func(to, subject string, macros map[string]string) error {
			called = "email"
			return nil
		},
	}

	msg, _ := json.Marshal(message{Type: "verification-email", To: "u@example.com", Subject: "Verify"})
	if err := c.routeActivation(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called != "email" {
		t.Fatalf("expected email handler, got %s", called)
	}

	if err := c.routeActivation(context.Background(), []byte{}); err == nil {
		t.Fatal("expected error for empty message")
	}
}

func TestRoutePasswordReset(t *testing.T) {
	called := ""
	c := &consumer{
		passwordResetSmsHandler: func(countryCode, to string, macros map[string]string) error {
			called = "sms"
			return nil
		},
		passwordResetEmailHandler: func(to, subject string, macros map[string]string) error {
			called = "email"
			return nil
		},
	}

	msg, _ := json.Marshal(message{Type: "password-reset-sms", CountryCode: "+1", To: "123"})
	if err := c.routePasswordReset(context.Background(), msg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if called != "sms" {
		t.Fatalf("expected sms handler, got %s", called)
	}

	if err := c.routePasswordReset(context.Background(), []byte("not-json")); err == nil {
		t.Fatal("expected error for invalid json")
	}
}
