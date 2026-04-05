package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"cdua-org/ReconSR/schema"
)

var commonSelectors = []string{
	"default", "google", "mail", "s1", "s2", "k1", "k2", "k3",
	"selector1", "fm1", "fm2", "pm", "protonmail", "proton",
	"zoho1", "zoho2", "smtp", "sendgrid", "sg", "mandrill", "pic",
	"x", "server", "dkim", "aws", "m1", "m2", "1", "2", "3",
	"zimbra", "yandex", "mailgun", "mg", "mailjet", "em", "em1", "em2",
}

func getDKIMData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_dkim",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	type dkimResult struct {
		selector string
		record   string
	}

	results := make(chan dkimResult, len(commonSelectors)+2)
	var wg sync.WaitGroup
	// Limit concurrency to avoid spamming the resolver too hard locally or remotely
	sem := make(chan struct{}, 10)

	// Dynamic selectors based on the first part of the target domain
	// For example.com -> example, for bondarenko.dn.ua -> bondarenko
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
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			domain := fmt.Sprintf("%s._domainkey.%s", sel, target)

			plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
				txts, err := r.LookupTXT(fallbackCtx, domain)
				if err != nil {
					return nil, fmt.Errorf("plain lookup dkim failed: %w", err)
				}
				return txts, nil
			}

			records, _, err := ResolveRecord(ctx, domain, 16, plainFallback)
			if err != nil || len(records) == 0 {
				return
			}

			for _, rec := range records {
				rec = strings.Trim(strings.TrimSpace(rec), "\"")
				if strings.HasPrefix(rec, "v=DKIM1") {
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
		rawDataBuilder.WriteString("._domainkey.")
		rawDataBuilder.WriteString(target)
		rawDataBuilder.WriteString(": ")
		rawDataBuilder.WriteString(res.record)

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   res.record,
			Context: "DKIM Selector: " + res.selector,
		})
	}

	if rawDataBuilder.Len() > 0 {
		execution.RawData = rawDataBuilder.String()
	}

	return execution
}
