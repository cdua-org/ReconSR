// Package domainsbycerts discovers subdomains from Certificate Transparency logs.
package domainsbycerts

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

const (
	timeFormatRFC3339 = "2006-01-02T15:04:05Z07:00"
	timeFormatDate    = "2006-01-02 15:04:05"
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

	execution.RawData = allDomains.rawData
	execution.Results = filterAndFormatDomains(allDomains.domains, target)

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

	fetchers := []CertFetcher{
		newCertspotterFetcher(),
		newCrtshFetcher(),
	}

	for _, f := range fetchers {
		entries := f.Fetch(ctx, target)
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
		}
	}

	if combined, err := json.Marshal(rawPayloads); err == nil {
		result.rawData = string(combined)
	}

	return result
}

func filterAndFormatDomains(domains []domainSource, target string) []schema.ModuleResult {
	domainMaxNotAfter := make(map[string]time.Time)
	domainSourceInfo := make(map[string]string)

	var targetMaxNotAfter time.Time
	var targetSource string

	for _, ds := range domains {
		d := normalizeDomain(ds.domain)
		if d == target {
			if ds.NotAfter.After(targetMaxNotAfter) {
				targetMaxNotAfter = ds.NotAfter
				targetSource = ds.source
			}
			continue
		}

		if !isValidSubdomain(d, target) {
			continue
		}

		if ds.NotAfter.After(domainMaxNotAfter[d]) {
			domainMaxNotAfter[d] = ds.NotAfter
			domainSourceInfo[d] = ds.source
		}
	}

	now := time.Now()
	var results []schema.ModuleResult
	var ghostDomains []string

	if !targetMaxNotAfter.IsZero() && targetMaxNotAfter.After(now) {
		results = append(results,
			schema.ModuleResult{
				Type:    "domain",
				Value:   target,
				Context: targetSource,
			},
			schema.ModuleResult{
				Type:    "string",
				Value:   targetMaxNotAfter.Format(time.RFC3339),
				Context: targetSource + " " + target + " expires on",
			})
	}

	for d, notAfter := range domainMaxNotAfter {
		if notAfter.IsZero() || notAfter.After(now) {
			results = append(results, schema.ModuleResult{
				Type:    "domain",
				Value:   d,
				Context: domainSourceInfo[d],
				Applied: true,
			})

			if !notAfter.IsZero() {
				results = append(results, schema.ModuleResult{
					Type:    "string",
					Value:   notAfter.Format(time.RFC3339),
					Context: domainSourceInfo[d] + " " + d + " expires on",
				})
			}
		} else {
			ghostDomains = append(ghostDomains, d)
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

	if t, err := time.Parse(timeFormatDate, ts); err == nil {
		return t
	}

	return time.Time{}
}
