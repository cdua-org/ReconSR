package dns

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

// parseURI decodes RFC 3597 wire format (\# <len> <hex>) for URI records (RFC 7553).
// Wire format: 2 bytes priority + 2 bytes weight + variable-length target URI.
func parseURI(raw string) string {
	if !strings.HasPrefix(raw, "\\# ") {
		return raw
	}

	// Format: \# <length> <hex>
	fields := strings.SplitN(raw, " ", 3)
	if len(fields) < 3 {
		return raw
	}

	data, err := hex.DecodeString(fields[2])
	if err != nil || len(data) < 4 {
		return raw
	}

	priority := binary.BigEndian.Uint16(data[0:2])
	weight := binary.BigEndian.Uint16(data[2:4])
	uri := string(data[4:])

	return fmt.Sprintf("%d %d %q", priority, weight, uri)
}

func getURIData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_uri",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 256, nil) // 256 is QTYPE for URI
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		parsed := parseURI(rec)

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   parsed,
			Context: "URI Record",
		})

		// URI data format: <priority> <weight> "<target-uri>"
		parts := strings.SplitN(parsed, " ", 3)
		if len(parts) < 3 {
			continue
		}

		uri := strings.Trim(parts[2], "\"")
		if uri == "" {
			continue
		}

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "url",
			Value:   uri,
			Context: "URI Endpoint",
		})
	}

	return execution
}
