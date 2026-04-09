package dns

import (
	"cdua-org/ReconSR/modules/utils/resolver"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

func getDMARCData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_dmarc",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dmarcTarget := "_dmarc." + target

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		txts, err := r.LookupTXT(fallbackCtx, dmarcTarget)
		if err != nil {
			return nil, fmt.Errorf("plain lookup dmarc failed: %w", err)
		}
		return txts, nil
	}

	// QTYPE 16 is TXT
	records, raw, err := resolver.ResolveRecord(ctx, dmarcTarget, 16, plainFallback)
	if err != nil {
		errMsg := "dmarc lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	} else if len(records) > 0 {
		execution.RawData = strings.Join(records, ", ")
	}

	dmarcRecords := filterDMARC(records)

	if len(dmarcRecords) == 0 {
		return execution
	}

	for _, rec := range dmarcRecords {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   rec,
			Context: "DMARC Record",
		})

		parsed := parseDMARC(rec)

		for _, key := range []string{"ruf", "rua"} {
			if val, ok := parsed[key]; ok {
				emails := extractEmails(val)
				for i, email := range emails {
					emailDomain := ""
					if _, after, found := strings.Cut(email, "@"); found {
						emailDomain = after
					}
					emailDomainLower := strings.ToLower(emailDomain)
					targetLower := strings.ToLower(target)
					isOOS := emailDomain != "" && emailDomainLower != targetLower && !strings.HasSuffix(emailDomainLower, "."+targetLower)

					contextMsg := "DMARC " + strings.ToUpper(key)
					if len(emails) > 1 {
						contextMsg = fmt.Sprintf("DMARC %s #%d", strings.ToUpper(key), i+1)
					}

					execution.Results = append(execution.Results, schema.ModuleResult{
						Type:       "email",
						Value:      email,
						Context:    contextMsg,
						OutOfScope: isOOS,
					})
				}
			}
		}
	}

	return execution
}

func filterDMARC(records []string) []string {
	var dmarc []string
	for _, rec := range records {
		rec = strings.Trim(strings.TrimSpace(rec), "\"")
		if strings.HasPrefix(rec, "v=DMARC1") {
			dmarc = append(dmarc, rec)
		}
	}
	return dmarc
}

func parseDMARC(record string) map[string]string {
	result := make(map[string]string)

	record = strings.TrimSpace(record)
	//nolint:modernize // SplitSeq is more efficient but Split is more widely compatible
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if idx := strings.Index(part, "="); idx > 0 {
			key := strings.TrimSpace(part[:idx])
			value := strings.TrimSpace(part[idx+1:])
			result[key] = value
		}
	}

	return result
}

func extractEmails(val string) []string {
	val = strings.TrimSpace(val)
	val = strings.TrimPrefix(val, "mailto:")

	var emails []string
	//nolint:modernize // strings.Split is widely compatible
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "mailto:")
		if part != "" && strings.Contains(part, "@") {
			emails = append(emails, part)
		}
	}
	return emails
}
