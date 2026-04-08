package dns

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var tlsaPrefixes = []string{
	"_443._tcp",
	"_443._udp",
	"_25._tcp",
	"_465._tcp",
	"_587._tcp",
	"_993._tcp",
	"_853._tcp",
}

type tlsaResult struct {
	prefix string
	record string
}

// parseTLSA decodes RFC 3597 wire format (\# <len> <hex>) for TLSA records (RFC 6698).
// Wire format: 1 byte Usage + 1 byte Selector + 1 byte Matching Type + variable length Association Data.
func parseTLSA(raw string) string {
	if !strings.HasPrefix(raw, "\\# ") {
		return raw
	}

	fields := strings.SplitN(raw, " ", 3)
	if len(fields) < 3 {
		return raw
	}

	hexStr := strings.ReplaceAll(fields[2], " ", "")
	data, err := hex.DecodeString(hexStr)
	if err != nil || len(data) < 3 {
		return raw
	}

	usage := data[0]
	selector := data[1]
	matchingType := data[2]
	hash := hex.EncodeToString(data[3:])

	return fmt.Sprintf("%d %d %d %s", usage, selector, matchingType, hash)
}

func getTLSAData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_tlsa",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// Direct + Brute force
	queries := append([]string{target}, func() []string {
		q := make([]string, 0, len(tlsaPrefixes))
		for _, p := range tlsaPrefixes {
			q = append(q, p+"."+target)
		}
		return q
	}()...)

	results := make(chan tlsaResult, len(queries))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, q := range queries {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			// QTYPE 52 is TLSA
			records, _, err := resolver.ResolveRecord(ctx, domain, 52, nil)
			if err != nil || len(records) == 0 {
				return
			}

			for _, rec := range records {
				prefix := strings.TrimSuffix(domain, "."+target)
				if prefix == domain {
					prefix = "@"
				}
				results <- tlsaResult{prefix: prefix, record: rec}
			}
		}(q)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var rawDataBuilder strings.Builder
	for res := range results {
		if rawDataBuilder.Len() > 0 {
			rawDataBuilder.WriteString("\n")
		}
		rawDataBuilder.WriteString(res.prefix)
		if res.prefix != "@" {
			rawDataBuilder.WriteString(".")
		}
		rawDataBuilder.WriteString(target)
		rawDataBuilder.WriteString(": ")
		rawDataBuilder.WriteString(res.record)

		parsed := parseTLSA(res.record)
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   parsed,
			Context: "TLSA Certificate Association (" + res.prefix + ")",
		})
	}

	if rawDataBuilder.Len() > 0 {
		execution.RawData = rawDataBuilder.String()
	}

	return execution
}
