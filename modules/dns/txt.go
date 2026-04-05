package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"cdua-org/ReconSR/schema"
)

func getTXTData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_txt",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	plainFallback := func(fallbackCtx context.Context, r *net.Resolver) ([]string, error) {
		txts, err := r.LookupTXT(fallbackCtx, target)
		if err != nil {
			return nil, fmt.Errorf("plain lookup txt failed: %w", err)
		}
		return txts, nil
	}

	// QTYPE 16 is TXT
	records, raw, err := ResolveRecord(ctx, target, 16, plainFallback)
	if err != nil {
		errMsg := "txt lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	} else if len(records) > 0 {
		execution.RawData = strings.Join(records, "\n")
	}

	var spfRecords []string
	var generalRecords []string

	for _, txt := range records {
		txt = strings.Trim(strings.TrimSpace(txt), "\"")
		if txt == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			spfRecords = append(spfRecords, txt)
		} else {
			generalRecords = append(generalRecords, txt)
		}
	}

	for _, spf := range spfRecords {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   spf,
			Context: "SPF Record",
		})
	}

	for _, txt := range generalRecords {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:    "string",
			Value:   txt,
			Context: "TXT Record",
		})
	}

	return execution
}
