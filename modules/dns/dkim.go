package dns

import (
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"cdua-org/ReconSR/schema"
)

var commonSelectors = []string{
	"default", "google", "mail", "s1", "s2", "k1", "k2", "k3",
	"selector1", "fm1", "fm2", "pm", "protonmail", "proton",
	"zoho1", "zoho2", "smtp", "sendgrid", "sg", "mandrill", "pic",
	"x", "server", "dkim", "aws", "m1", "m2", "1", "2", "3",
	"zimbra", "yandex", "mailgun", "mg", "mailjet", "em", "em1", "em2",
}

func getDKIMData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetDKIM)
	log.Printf("%s query_start target=%q", constants.FuncGetDKIM, target)

	bruteCtx, cancel := context.WithTimeout(ctx, resolver.DNSBruteTimeout)
	defer cancel()

	type dkimResult struct {
		selector string
		record   string
	}

	results := make(chan dkimResult, len(commonSelectors)+2)
	var wg sync.WaitGroup
	sem := make(chan struct{}, resolver.DNSConcurrency)

	firstPart := strings.Split(target, ".")[0]
	dynamicSelectors := []string{
		"mail." + firstPart,
		firstPart,
	}

	allSelectors := make([]string, 0, len(commonSelectors)+len(dynamicSelectors))
	allSelectors = append(allSelectors, commonSelectors...)
	allSelectors = append(allSelectors, dynamicSelectors...)

	for _, selector := range allSelectors {
		wg.Add(1)

		go func(sel string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
			case <-bruteCtx.Done():
				return
			}
			defer func() { <-sem }()

			domain := fmt.Sprintf("%s.%s.%s", sel, domainKeyLabel, target)

			plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
				txts, err := r.LookupTXT(fallbackCtx, domain)
				if err != nil {
					return nil, fmt.Errorf("plain lookup dkim failed: %w", err)
				}
				return txts, nil
			}

			records, _, err := resolver.ResolveRecord(bruteCtx, domain, 16, plainFallback)
			if err != nil || len(records) == 0 {
				return
			}

			for _, rec := range records {
				rec = strings.Trim(strings.TrimSpace(rec), "\"")
				if strings.HasPrefix(rec, "v=DKIM1") {
					log.Printf("%s success target=%q selector=%q found=true", constants.FuncGetDKIM, target, sel)
					results <- dkimResult{selector: sel, record: rec}
				}
			}
		}(selector)
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
		rawDataBuilder.WriteString(res.selector)
		rawDataBuilder.WriteString(".")
		rawDataBuilder.WriteString(domainKeyLabel)
		rawDataBuilder.WriteString(".")
		rawDataBuilder.WriteString(target)
		rawDataBuilder.WriteString(": ")
		rawDataBuilder.WriteString(res.record)

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDKIM,
			Category: constants.CategoryProperty,
			Value:    res.record,
			Context:  "DKIM Selector: " + res.selector,
			LocalID:  gen.NextID(),
		})
	}

	if rawDataBuilder.Len() > 0 {
		exec.RawData = rawDataBuilder.String()
	}

	log.Printf("%s success target=%q results=%d", constants.FuncGetDKIM, target, len(exec.Results))
	return exec
}
