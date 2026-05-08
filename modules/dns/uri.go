package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func parseURI(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 4)
	if !ok {
		return raw
	}

	priority := binary.BigEndian.Uint16(data[0:2])
	weight := binary.BigEndian.Uint16(data[2:4])
	uri := string(data[4:])

	return fmt.Sprintf("%d %d %q", priority, weight, uri)
}

func getURIData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetURI)

	log.Printf("get_uri target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 256, nil)
	if err != nil {
		log.Printf("get_uri error: %v", err)
		modutil.SetError(&exec, "uri lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	log.Printf("get_uri target=%q records=%d", target, len(records))

	for _, rec := range records {
		parsed := parseURI(rec)

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeURI,
			Category: constants.CategoryProperty,
			Value:    parsed,
			Context:  "URI Record",
		})

		parts := strings.SplitN(parsed, " ", 3)
		if len(parts) < 3 {
			continue
		}

		uri := strings.Trim(parts[2], "\"")
		if uri == "" {
			continue
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeURL,
			Category: constants.CategoryProperty,
			Value:    uri,
			Context:  "URI Endpoint",
		})
	}

	return exec
}
