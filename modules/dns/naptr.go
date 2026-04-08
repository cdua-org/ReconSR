package dns

import (
	"context"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

// parseNAPTRRecord attempts to extract the components of a native NAPTR text format.
// Format: <order> <preference> "<flags>" "<services>" "<regexp>" <replacement>
// Returns the parsed string if successful, or raw if it's already wire/unparseable.
func parseNAPTRRecord(raw string) string {
	if strings.HasPrefix(raw, "\\# ") {
		return raw
	}
	return raw
}

// parseNativeNAPTR splits a standard NAPTR record string taking quotes into account.
func parseNativeNAPTR(parsed string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for _, r := range parsed {
		switch {
		case r == '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case r == ' ' && !inQuotes:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

func getNAPTRData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_naptr",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 35, nil) // 35 is QTYPE for NAPTR
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		parsed := parseNAPTRRecord(rec)

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   parsed,
			Context: "NAPTR Record",
		})

		if strings.HasPrefix(parsed, "\\# ") {
			continue
		}

		parts := parseNativeNAPTR(parsed)
		if len(parts) < 6 {
			continue
		}

		svc := strings.Trim(parts[3], "\"")
		if svc != "" {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:    "string",
				Value:   svc,
				Context: "NAPTR Service",
			})
		}

		repl := strings.Trim(parts[5], ".")
		if repl != "" && repl != "." && !strings.ContainsAny(repl, " \"") {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:    "domain",
				Value:   repl,
				Context: "NAPTR Replacement Domain",
			})
		}
	}

	return execution
}
