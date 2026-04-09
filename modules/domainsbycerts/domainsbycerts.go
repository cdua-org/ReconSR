// Package domainsbycerts discovers subdomains from Certificate Transparency logs.
package domainsbycerts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

const (
	timeFormatRFC3339  = "2006-01-02T15:04:05Z07:00"
	timeFormatDateTime = "2006-01-02T15:04:05"
	timeFormatDate     = "2006-01-02 15:04:05"
)

type module struct{}

// New instantiates the module for registration within the dispatcher's lifecycle.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "domainsbycerts"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{"get_domains"},
		InputTypes: []string{"domain"},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == "get_domains" {
			execution = getDomains(data.Target.Value)
		} else {
			errMsg := "unsupported function: " + f
			execution = schema.ModuleExecution{
				Function: f,
				Error:    &errMsg,
			}
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func getDomains(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_domains",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	allDomains := collectAllDomains(ctx, target)

	if len(allDomains.domains) == 0 {
		errMsg := "all cert discovery methods exhausted for " + target
		execution.Error = &errMsg
		return execution
	}

	disableGhostDomains := false
	if val, ok := resolver.GetOption("DisableGhostDomains"); ok && strings.EqualFold(val, "true") {
		disableGhostDomains = true
	}

	execution.RawData = allDomains.rawData
	classified := classifyDomains(allDomains.domains, target)
	execution.Results = formatResults(classified, target, disableGhostDomains)

	sort.Slice(execution.Results, func(i, j int) bool {
		return execution.Results[i].Value < execution.Results[j].Value
	})

	return execution
}

type domainSource struct {
	NotAfter time.Time
	domain   string
	source   string
}

type collectedDomains struct {
	rawData string
	domains []domainSource
}

type domainEntry struct {
	domain   string
	notAfter time.Time
	rawData  json.RawMessage
}

// CertFetcher defines the interface for certificate transparency APIs.
type CertFetcher interface {
	Fetch(ctx context.Context, target string) []domainEntry
	Name() string
}

func collectAllDomains(ctx context.Context, target string) collectedDomains {
	var result collectedDomains
	rawPayloads := make(map[string]json.RawMessage)
	debug := isDebug()

	disableCertspotter := false
	if val, ok := resolver.GetOption("DisableCertspotter"); ok && strings.EqualFold(val, "true") {
		disableCertspotter = true
	}

	var fetchers []CertFetcher
	if !disableCertspotter {
		fetchers = append(fetchers, newCertspotterFetcher())
	} else if debug {
		fmt.Fprintf(os.Stderr, "[certs-debug] Certspotter disabled via config\n")
	}
	fetchers = append(fetchers, newCrtshFetcher())

	for _, f := range fetchers {
		entries := f.Fetch(ctx, target)

		if debug {
			fmt.Fprintf(os.Stderr, "[certs-debug] fetcher=%q target=%q entries=%d\n", f.Name(), target, len(entries))
		}

		if len(entries) > 0 {
			for _, e := range entries {
				result.domains = append(result.domains, domainSource{
					domain:   e.domain,
					source:   f.Name(),
					NotAfter: e.notAfter,
				})
			}
			if len(rawPayloads) == 0 {
				rawPayloads[f.Name()] = entries[0].rawData
			}
			// Skip remaining fetchers to conserve resources since CT logs heavily overlap
			break
		}
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[certs-debug] totalDomains=%d\n", len(result.domains))
	}

	if combined, err := json.Marshal(rawPayloads); err == nil {
		result.rawData = string(combined)
	}

	return result
}

type classifiedDomains struct {
	subdomains       map[string]time.Time // domain -> max NotAfter
	subdomainSources map[string]string    // domain -> source name
	targetMaxExpiry  time.Time
	targetSource     string
}

func classifyDomains(domains []domainSource, target string) classifiedDomains {
	result := classifiedDomains{
		subdomains:       make(map[string]time.Time),
		subdomainSources: make(map[string]string),
	}
	debug := isDebug()
	var targetCount, invalidCount, subdomainCount int

	for _, ds := range domains {
		d := normalizeDomain(ds.domain)
		if d == target {
			targetCount++
			if ds.NotAfter.After(result.targetMaxExpiry) {
				result.targetMaxExpiry = ds.NotAfter
				result.targetSource = ds.source
			}
			continue
		}

		if !isValidSubdomain(d, target) {
			invalidCount++
			if debug && invalidCount <= 10 {
				fmt.Fprintf(os.Stderr, "[certs-debug] rejected domain=%q (not a subdomain of %q)\n", d, target)
			}
			continue
		}

		subdomainCount++
		if ds.NotAfter.After(result.subdomains[d]) {
			result.subdomains[d] = ds.NotAfter
			result.subdomainSources[d] = ds.source
		}
	}

	if debug {
		fmt.Fprintf(os.Stderr, "[certs-debug] filter: targetHits=%d invalidSkipped=%d validSubdomains=%d uniqueSubdomains=%d\n",
			targetCount, invalidCount, subdomainCount, len(result.subdomains))
	}

	return result
}

func formatResults(classified classifiedDomains, target string, disableGhostDomains bool) []schema.ModuleResult {
	now := time.Now()
	var results []schema.ModuleResult
	var ghostDomains []string

	if !classified.targetMaxExpiry.IsZero() && classified.targetMaxExpiry.After(now) {
		results = append(results,
			schema.ModuleResult{
				Type:    "domain",
				Value:   target,
				Context: classified.targetSource,
			},
			schema.ModuleResult{
				Type:    "string",
				Value:   classified.targetMaxExpiry.Format(time.RFC3339),
				Context: classified.targetSource + " " + target + " expires on",
			})
	}

	for d, notAfter := range classified.subdomains {
		isExpired := !notAfter.IsZero() && !notAfter.After(now)

		if isExpired && !disableGhostDomains {
			ghostDomains = append(ghostDomains, d)
			continue
		}

		srcContext := classified.subdomainSources[d]
		if isExpired && disableGhostDomains {
			srcContext += " (Ghost)"
		}

		results = append(results, schema.ModuleResult{
			Type:    "domain",
			Value:   d,
			Context: srcContext,
			Applied: true,
		})

		if !notAfter.IsZero() {
			results = append(results, schema.ModuleResult{
				Type:    "string",
				Value:   notAfter.Format(time.RFC3339),
				Context: srcContext + " " + d + " expires on",
			})
		}
	}

	if len(ghostDomains) > 0 {
		sort.Strings(ghostDomains)
		results = append(results, schema.ModuleResult{
			Type:    "string",
			Value:   strings.Join(ghostDomains, ", "),
			Context: "Ghost subdomains",
		})
	}

	if isDebug() {
		fmt.Fprintf(os.Stderr, "[certs-debug] output: results=%d ghostDomains=%d\n", len(results), len(ghostDomains))
	}

	return results
}

func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "*.")
	return d
}

func isValidSubdomain(d, target string) bool {
	return d != "" && d != target && strings.HasSuffix(d, "."+target)
}

func parseCertTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}

	if t, err := time.Parse(timeFormatRFC3339, ts); err == nil {
		return t
	}

	if t, err := time.Parse(timeFormatDateTime, ts); err == nil {
		return t
	}

	if t, err := time.Parse(timeFormatDate, ts); err == nil {
		return t
	}

	return time.Time{}
}
