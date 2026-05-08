package shodan

import (
	"testing"

	"cdua-org/ReconSR/schema"
)

func shodanTestAPIKey() string {
	return "test-key"
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

func requireTaggedResults(t *testing.T, results []schema.ModuleResult, expectedTag string) {
	t.Helper()

	for _, result := range results {
		if len(result.Tags) != 1 || result.Tags[0] != expectedTag {
			t.Fatalf("expected tag %q, got %+v", expectedTag, result.Tags)
		}
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
