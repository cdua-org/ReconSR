package dns

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
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

func parseTLSA(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 4)
	if !ok {
		return raw
	}

	usage := data[0]
	selector := data[1]
	matchingType := data[2]
	hash := hex.EncodeToString(data[3:])

	return fmt.Sprintf("%d %d %d %s", usage, selector, matchingType, hash)
}

func getTLSAData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetTLSA)
	log.Printf("%s query_start target=%q", constants.FuncGetTLSA, target)

	bruteCtx, cancel := context.WithTimeout(ctx, resolver.DNSBruteTimeout)
	defer cancel()

	queries := append([]string{target}, func() []string {
		q := make([]string, 0, len(tlsaPrefixes))
		for _, p := range tlsaPrefixes {
			q = append(q, p+"."+target)
		}
		return q
	}()...)

	results := make(chan tlsaResult, len(queries))
	var wg sync.WaitGroup
	sem := make(chan struct{}, resolver.DNSConcurrency)

	for _, q := range queries {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-bruteCtx.Done():
				return
			}
			defer func() { <-sem }()

			records, _, err := resolver.ResolveRecord(bruteCtx, domain, 52, nil)
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
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTLSA,
			Category: constants.CategoryProperty,
			Value:    parsed,
			Context:  "TLSA Certificate Association (" + res.prefix + ")",
		})
	}

	if rawDataBuilder.Len() > 0 {
		exec.RawData = rawDataBuilder.String()
	}

	log.Printf("%s success target=%q results=%d", constants.FuncGetTLSA, target, len(exec.Results))
	return exec
}
