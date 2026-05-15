package shodan

import (
	"os"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func shodanTestAPIKey() string {
	return "test-key"
}

func shodanTestPreflightPath() string {
	return "/api-info"
}

func shodanTestAPIIPv4() string {
	return "198.51.100.1"
}

func internetDBTestIPv4() string {
	return "192.0.2.1"
}

func findModuleResult(results []schema.ModuleResult, resultType, value string) (schema.ModuleResult, bool) {
	for _, result := range results {
		if result.Type == resultType && result.Value == value {
			return result, true
		}
	}

	return schema.ModuleResult{}, false
}

func requireModuleResult(t *testing.T, results []schema.ModuleResult, resultType, value string) schema.ModuleResult {
	t.Helper()

	result, ok := findModuleResult(results, resultType, value)
	if !ok {
		t.Fatalf("expected result %s=%q, got %+v", resultType, value, results)
	}

	return result
}

func requireTagPropertyResults(t *testing.T, results []schema.ModuleResult, expectedTags ...string) {
	t.Helper()

	actualTags := make([]string, 0, len(expectedTags))
	for _, result := range results {
		if len(result.Tags) > 0 {
			hasOnlyAllowedTag := len(result.Tags) == 1 && (result.Tags[0] == constants.TagMX || result.Tags[0] == constants.TagSRV || result.Tags[0] == constants.TagNAPTR || result.Tags[0] == constants.TagCNAME || result.Tags[0] == constants.TagCAA)
			if !hasOnlyAllowedTag {
				t.Fatalf("expected no system tags assigned via Tags field, got %+v", result)
			}
		}
		if result.Type != constants.TypeTag {
			continue
		}
		if result.Category != constants.CategoryProperty {
			t.Fatalf("expected tag result to be a property, got %+v", result)
		}
		actualTags = append(actualTags, result.Value)
	}

	if !slices.Equal(actualTags, expectedTags) {
		t.Fatalf("expected informational tags %v, got %v", expectedTags, actualTags)
	}
}

func requireModuleResultWithContext(t *testing.T, results []schema.ModuleResult, resultType, value, context string) schema.ModuleResult {
	t.Helper()

	for _, result := range results {
		if result.Type == resultType && result.Value == value && result.Context == context {
			return result
		}
	}

	t.Fatalf("expected result %s=%q context=%q not found", resultType, value, context)
	return schema.ModuleResult{}
}

func findModuleResultBySource(results []schema.ModuleResult, resultType, sourceType, sourceValue string) *schema.ModuleResult {
	for i, result := range results {
		if result.Type != resultType {
			continue
		}

		if sourceType == "" && sourceValue == "" {
			if result.Source == nil {
				return &results[i]
			}

			continue
		}

		if result.Source != nil && result.Source.Type == sourceType && result.Source.Value == sourceValue {
			return &results[i]
		}
	}

	return nil
}

func loadShodanFixture(t *testing.T, filename string) []byte {
	t.Helper()

	var (
		data []byte
		err  error
	)

	switch filename {
	case "domain.json":
		data, err = os.ReadFile("testdata/domain.json")
	case "ip_full.json":
		data, err = os.ReadFile("testdata/ip_full.json")
	case "ip_escaped_san.json":
		data, err = os.ReadFile("testdata/ip_escaped_san.json")
	case "ip_duplicate_webserver.json":
		data, err = os.ReadFile("testdata/ip_duplicate_webserver.json")
	case "ip_heartbleed.json":
		data, err = os.ReadFile("testdata/ip_heartbleed.json")
	case "ip_port_fallback.json":
		data, err = os.ReadFile("testdata/ip_port_fallback.json")
	default:
		t.Fatalf("unsupported fixture %s", filename)
	}
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", filename, err)
	}
	return data
}
