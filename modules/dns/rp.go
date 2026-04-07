package dns

import (
	"context"
	"strings"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

// parseRPMailbox converts RFC 1183 mailbox format (first.last.example.com.)
// into a standard email address (first.last@example.com).
// The first dot in the mailbox name acts as the '@' separator.
func parseRPMailbox(mbox string) string {
	mbox = strings.TrimSuffix(mbox, ".")

	// A single dot means "root mailbox of the domain" — skip conversion
	idx := strings.Index(mbox, ".")
	if idx <= 0 || idx == len(mbox)-1 {
		return mbox
	}

	return mbox[:idx] + "@" + mbox[idx+1:]
}

func getRPData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_rp",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(ctx, target, 17, nil) // 17 is QTYPE for RP
	if err != nil {
		errStr := err.Error()
		execution.Error = &errStr
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	for _, rec := range records {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   rec,
			Context: "Responsible Person",
		})

		parts := strings.Fields(rec)
		if len(parts) < 2 {
			continue
		}

		// First field: mailbox in DNS format
		mailbox := parseRPMailbox(parts[0])
		if mailbox != "." && mailbox != "" {
			res, vErr := validator.Validate("email", mailbox)
			if vErr == nil {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    res.Type,
					Value:   res.Value,
					Context: "RP Administrator Email",
				})
			}
		}

		// Second field: TXT domain reference
		txtDomain := strings.TrimSuffix(parts[1], ".")
		if txtDomain != "." && txtDomain != "" {
			res, vErr := validator.Validate("domain", txtDomain)
			if vErr == nil {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    res.Type,
					Value:   res.Value,
					Context: "RP TXT Reference Domain",
				})
			}
		}
	}

	return execution
}
