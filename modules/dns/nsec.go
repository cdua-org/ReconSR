package dns

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/schema"
)

//nolint:gocyclo // processing loop complexity is acceptable
func getNSECData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_nsec",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	// Prevent recursive zone walking on our own nx- probes
	if strings.HasPrefix(strings.ToLower(target), "nx-") {
		return execution
	}

	bytes := make([]byte, 6)
	_, _ = rand.Read(bytes)
	nxTarget := "nx-" + hex.EncodeToString(bytes) + "." + target

	type queryConfig struct {
		queryTarget string
		contextDesc string
		qtype       int
	}

	queries := []queryConfig{
		{target, "Direct NSEC", 47},         // NSEC = 47
		{target, "Direct NSEC3", 50},        // NSEC3 = 50
		{nxTarget, "Zone Walk NXDOMAIN", 1}, // A = 1, triggers NSEC/NSEC3 in Authority
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	var rawDataBuilder strings.Builder

	for _, req := range queries {
		wg.Add(1)
		go func(q queryConfig) {
			defer wg.Done()

			resp, raw, err := resolver.QueryDoHDns(ctx, q.queryTarget, q.qtype)
			if err != nil || resp == nil {
				return
			}

			mu.Lock()
			if rawDataBuilder.Len() > 0 {
				rawDataBuilder.WriteString("\n")
			}
			// Just store raw data block
			rawDataBuilder.Write(raw)

			// Helper to process NSEC3 specifically
			processNSEC3 := func(rec resolver.DoHDnsRecord) {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   rec.Name + " NSEC3 " + rec.Data,
					Context: q.contextDesc,
				})

				hashPart := strings.Split(rec.Name, ".")[0]
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   hashPart,
					Context: "NSEC3 Hash",
				})

				parts := strings.Fields(rec.Data)
				if len(parts) >= 5 {
					execution.Results = append(execution.Results, schema.ModuleResult{
						Type:    "string",
						Value:   parts[4],
						Context: "NSEC3 Next Hash",
					})
				}
			}

			// Helper to process NSEC specifically
			processNSEC := func(rec resolver.DoHDnsRecord) {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   rec.Name + " NSEC " + rec.Data,
					Context: q.contextDesc,
				})

				parts := strings.Fields(rec.Data)
				if len(parts) > 0 {
					nextDomain := strings.TrimSuffix(parts[0], ".")
					_, err := validator.Validate("domain", nextDomain)
					validTarget := !strings.EqualFold(nextDomain, target) && !strings.EqualFold(nextDomain, nxTarget)
					validSuffix := strings.HasSuffix(strings.ToLower(nextDomain), "."+strings.ToLower(target))

					if err == nil && validTarget && validSuffix {
						execution.Results = append(execution.Results, schema.ModuleResult{
							Type:    "domain",
							Value:   nextDomain,
							Context: "NSEC Leaked Subdomain",
						})
					}
				}

				currentDomain := strings.TrimSuffix(rec.Name, ".")
				_, err := validator.Validate("domain", currentDomain)
				validTarget := currentDomain != "" && !strings.EqualFold(currentDomain, target) && !strings.EqualFold(currentDomain, nxTarget)
				validSuffix := strings.HasSuffix(strings.ToLower(currentDomain), "."+strings.ToLower(target))

				if err == nil && validTarget && validSuffix {
					execution.Results = append(execution.Results, schema.ModuleResult{
						Type:    "domain",
						Value:   currentDomain,
						Context: "NSEC Current Subdomain",
					})
				}
			}

			// Helper to process records dynamically from Answer or Authority
			processRecords := func(records []resolver.DoHDnsRecord) {
				for _, rec := range records {
					switch rec.Type {
					case 47:
						processNSEC(rec)
					case 50:
						processNSEC3(rec)
					}
				}
			}

			// Process Answer and Authority sections
			processRecords(resp.Answer)
			if resp.Status == 3 || q.qtype == 1 {
				// NXDOMAIN might have NSEC/NSEC3 in Authority
				processRecords(resp.Authority)
			}

			mu.Unlock()
		}(req)
	}

	wg.Wait()

	if rawDataBuilder.Len() > 0 {
		execution.RawData = rawDataBuilder.String()
	}

	return execution
}
