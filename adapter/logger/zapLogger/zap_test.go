package zapLogger

import (
	"strings"
	"testing"
)

func TestStringToZapLevel(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "error", input: "error"},
		{name: "warn", input: "warn"},
		{name: "info", input: "info"},
		{name: "debug", input: "debug"},
		{name: "invalid", input: "verbose", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := stringToZapLevel(tt.input)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestGetFunctionName(t *testing.T) {
	file, line, fn := getFunctionName(0)
	if file == "unknown" || line == 0 || fn == "unknown" {
		t.Fatalf("unexpected function metadata: file=%q line=%d fn=%q", file, line, fn)
	}
	if !strings.Contains(fn, "getFunctionName") {
		t.Fatalf("expected function name to include getFunctionName, got %q", fn)
	}
}
