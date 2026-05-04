package asn_metadata

import (
	"context"

	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

func getASNPrefixes(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution("get_asn_prefixes")

	dbg.Printf("getASNPrefixes target=%q", target)

	originASN := target
	if originASN == "" {
		errMsg := errInvalidASNFormat
		execution.Error = &errMsg
		dbg.Printf("getASNPrefixes target=%q invalid_format", target)
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.TimeoutASNMeta)
	defer cancel()

	var resp ripestat.AnnouncedPrefixesResponse
	defer func() {
		execution.RawData = resp.RawJSON
	}()

	if err := ripestat.Query(ctx, originASN, "announced-prefixes", &resp, resolver.MaxRetriesASNMeta); err != nil {
		errMsg := "asn prefixes lookup failed: " + err.Error()
		execution.Error = &errMsg
		dbg.Printf("getASNPrefixes target=%q lookup_error=%v", target, err)
		return execution
	}

	execution.Results = append(execution.Results, schema.ModuleResult{
		Type:     "asn",
		Category: "node",
		Value:    originASN,
		Context:  "Origin AS",
		Applied:  true,
	})

	for _, p := range resp.Data.Prefixes {
		if p.Prefix != "" {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     "cidr",
				Category: "property",
				Value:    p.Prefix,
				Context:  "Announced Prefix",
			})
		}
	}

	dbg.Printf("getASNPrefixes target=%q found_prefixes=%d", target, len(resp.Data.Prefixes))

	return execution
}
