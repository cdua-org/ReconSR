package dns

import (
	"context"
	"slices"
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestParseHIP(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			"standard hip wire format",
			"\\# 18 08020004010203040506070801020304",
			"2 0102030405060708 AQIDBA==",
		},
		{
			"passthrough hip text",
			"2 200100107B1A74DF365639CC39F1D578 AwEAAb rv1.example.net.",
			"2 200100107B1A74DF365639CC39F1D578 AwEAAb rv1.example.net.",
		},
		{
			"invalid hex data",
			"\\# 18 ZZ",
			"\\# 18 ZZ",
		},
		{
			"out of bounds pklen",
			"\\# 6 0802FFFF0102",
			"\\# 6 0802FFFF0102",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseHIP(tt.input)
			if got != tt.expected {
				t.Errorf("parseHIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestGetHIPDataEmpty(t *testing.T) {
	execution := getHIPData(context.Background(), "example.com", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Logf("hip lookup failed: %v", *execution.Error)
		return
	}

	t.Logf("Found %d HIP results for example.com", len(execution.Results))
}

func TestGetHIPDataNX(t *testing.T) {
	execution := getHIPData(context.Background(), "nonexistent.domain.invalid", modutil.NewLocalIDGenerator())

	if execution.Error != nil && !strings.Contains(*execution.Error, "status 3") {
		t.Logf("hip lookup failed: %v", *execution.Error)
	}
}

func TestBuildHIPResultsUsesSemanticServerType(t *testing.T) {
	results := buildHIPResults("2 200100107B1A74DF365639CC39F1D578 AwEAAb rv1.example.net.", "semantic.hip.example.com", modutil.NewLocalIDGenerator())
	if len(results) != 2 {
		t.Fatalf("buildHIPResults() returned %d results, want 2", len(results))
	}

	assertHIPResults(t, results, "AwEAAb", "rv1.example.net", true)
}

func TestParseHIPRecordBuildsSemanticServerResult(t *testing.T) {
	results := buildHIPResults(parseHIP("2 200100107B1A74DF365639CC39F1D578 AwEAAb rv1.example.net."), "parse.hip.example.com", modutil.NewLocalIDGenerator())
	if len(results) != 2 {
		t.Fatalf("buildHIPResults(parseHIP()) returned %d results, want 2", len(results))
	}

	assertHIPResults(t, results, "AwEAAb", "rv1.example.net", true)
}

func TestBuildHIPResultsEmptyRendezvousSkipsNode(t *testing.T) {
	results := buildHIPResults("2 200100107B1A74DF365639CC39F1D578 AwEAAb .", "empty.hip.example.com", modutil.NewLocalIDGenerator())
	if len(results) != 1 {
		t.Fatalf("buildHIPResults() returned %d results, want 1", len(results))
	}
	if results[0].Type != constants.TypeHIP {
		t.Fatalf("Type = %q, want %q", results[0].Type, constants.TypeHIP)
	}
}

func TestBuildHIPResultsInvalidRendezvousSkipsNode(t *testing.T) {
	results := buildHIPResults("2 200100107B1A74DF365639CC39F1D578 AwEAAb rv_1.example.net.", "invalid.hip.example.com", modutil.NewLocalIDGenerator())
	if len(results) != 1 {
		t.Fatalf("buildHIPResults() returned %d results, want 1", len(results))
	}
	if results[0].Type != constants.TypeHIP {
		t.Fatalf("Type = %q, want %q", results[0].Type, constants.TypeHIP)
	}
}

func TestBuildHIPResultsSelfReferentialSkipsNode(t *testing.T) {
	results := buildHIPResults("2 200100107B1A74DF365639CC39F1D578 AwEAAb example.com.", "example.com", modutil.NewLocalIDGenerator())
	if len(results) != 1 {
		t.Fatalf("buildHIPResults() returned %d results, want 1", len(results))
	}
	if results[0].Type != constants.TypeHIP {
		t.Fatalf("Type = %q, want %q", results[0].Type, constants.TypeHIP)
	}
}

func TestBuildHIPResultsNormalizesRendezvousServer(t *testing.T) {
	results := buildHIPResults("2 200100107B1A74DF365639CC39F1D578 AwEAAb RV1.EXAMPLE.NET.", "normalize.hip.example.com", modutil.NewLocalIDGenerator())
	if len(results) != 2 {
		t.Fatalf("buildHIPResults() returned %d results, want 2", len(results))
	}

	assertHIPResults(t, results, "AwEAAb", "rv1.example.net", true)
}

func TestHIPCapabilities(t *testing.T) {
	m := &module{}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("unexpected error getting capabilities: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetHIP) {
		t.Error("expected get_hip in capabilities")
	}
}

func assertHIPResults(t *testing.T, results []schema.ModuleResult, wantPubKey, wantHost string, wantOOS bool) {
	t.Helper()

	propertyResult := results[0]
	if propertyResult.Type != constants.TypeHIP {
		t.Fatalf("property Type = %q, want %q", propertyResult.Type, constants.TypeHIP)
	}
	if propertyResult.Category != constants.CategoryProperty {
		t.Fatalf("property Category = %q, want %q", propertyResult.Category, constants.CategoryProperty)
	}
	if propertyResult.Value != wantPubKey {
		t.Fatalf("property Value = %q, want %q", propertyResult.Value, wantPubKey)
	}

	nodeResult := results[1]
	if nodeResult.Type != constants.TypeSubdomain {
		t.Fatalf("node Type = %q, want %q", nodeResult.Type, constants.TypeSubdomain)
	}
	if !slices.Contains(nodeResult.Tags, constants.TagHIP) {
		t.Fatalf("node Tags missing %q", constants.TagHIP)
	}
	if nodeResult.Category != constants.CategoryNode {
		t.Fatalf("node Category = %q, want %q", nodeResult.Category, constants.CategoryNode)
	}
	if nodeResult.Value != wantHost {
		t.Fatalf("node Value = %q, want %q", nodeResult.Value, wantHost)
	}
	if nodeResult.Context != "HIP Rendezvous Server" {
		t.Fatalf("node Context = %q, want %q", nodeResult.Context, "HIP Rendezvous Server")
	}
	if nodeResult.OutOfScope != wantOOS {
		t.Fatalf("node OutOfScope = %v, want %v", nodeResult.OutOfScope, wantOOS)
	}
	if nodeResult.Source == nil {
		t.Fatal("node Source = nil, want HIP property source")
	}
	if nodeResult.Source.Type != propertyResult.Type || nodeResult.Source.Value != propertyResult.Value {
		t.Fatalf("node Source = %+v, want type=%q value=%q", *nodeResult.Source, propertyResult.Type, propertyResult.Value)
	}
}
