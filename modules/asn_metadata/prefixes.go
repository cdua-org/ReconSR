package asn_metadata

import (
	"context"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

func getASNPrefixes(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetASNPrefixes)

	dbg.Printf("%s target=%q", constants.FuncGetASNPrefixes, target)

	originASN := target
	if originASN == "" {
		errMsg := errInvalidASNFormat
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=validate_input err=invalid_asn_format", constants.FuncGetASNPrefixes, target)
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.TimeoutASNMeta)
	defer cancel()

	var resp ripestat.AnnouncedPrefixesResponse
	defer func() {
		execution.RawData = resp.RawJSON
	}()

	if err := ripestat.Query(ctx, originASN, constants.RIPEstatEndpointAnnouncedPrefixes, &resp, resolver.MaxRetriesASNMeta); err != nil {
		errMsg := "asn prefixes lookup failed: " + err.Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=query_lookup err=%v", constants.FuncGetASNPrefixes, target, err)
		return execution
	}

	execution.Results = append(execution.Results, schema.ModuleResult{
		Type:     constants.TypeASN,
		Category: constants.CategoryNode,
		Value:    originASN,
		Context:  "Origin AS",
		Applied:  true,
	})

	for _, p := range resp.Data.Prefixes {
		if p.Prefix != "" {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeCIDR,
				Category: constants.CategoryProperty,
				Value:    p.Prefix,
				Context:  "Announced Prefix",
			})
		}
	}

	dbg.Printf("%s success target=%q found_prefixes=%d", constants.FuncGetASNPrefixes, target, len(resp.Data.Prefixes))

	return execution
}
