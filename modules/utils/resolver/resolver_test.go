package resolver

import (
	"strconv"
	"testing"
)

func TestDebugConsoleOption(t *testing.T) {
	oldDebug, hadDebug := Options["Debug"]
	oldDebugConsole, hadDebugConsole := Options["DebugConsole"]
	defer func() {
		if hadDebug {
			Options["Debug"] = oldDebug
		} else {
			delete(Options, "Debug")
		}
		if hadDebugConsole {
			Options["DebugConsole"] = oldDebugConsole
		} else {
			delete(Options, "DebugConsole")
		}
	}()

	tests := []struct {
		name         string
		debug        string
		debugConsole string
		want         bool
	}{
		{name: "unset console", debug: strconv.FormatBool(true), debugConsole: "", want: false},
		{name: "console enabled", debug: strconv.FormatBool(true), debugConsole: strconv.FormatBool(true), want: true},
		{name: "master disabled", debug: strconv.FormatBool(false), debugConsole: strconv.FormatBool(true), want: false},
		{name: "console false", debug: strconv.FormatBool(true), debugConsole: strconv.FormatBool(false), want: false},
	}

	for _, tt := range tests {
		Options["Debug"] = tt.debug
		if tt.debugConsole == "" {
			delete(Options, "DebugConsole")
		} else {
			Options["DebugConsole"] = tt.debugConsole
		}

		if got := isDebugConsole(); got != tt.want {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.want, got)
		}
	}
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected string
		isIPv4   bool
		isErr    bool
	}{
		{"192.0.2.1", "1.2.0.192", true, false},
		{"198.51.100.2", "2.100.51.198", true, false},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2", false, false},
		{"invalid", "", false, true},
	}

	for _, tt := range tests {
		rev, isIPv4, err := ReverseIP(tt.ip)
		if (err != nil) != tt.isErr {
			t.Errorf("ip %q: expected error %v, got %v", tt.ip, tt.isErr, err)
		}
		if rev != tt.expected {
			t.Errorf("ip %q: expected %q, got %q", tt.ip, tt.expected, rev)
		}
		if isIPv4 != tt.isIPv4 {
			t.Errorf("ip %q: expected isIPv4 %v, got %v", tt.ip, tt.isIPv4, isIPv4)
		}
	}
}
