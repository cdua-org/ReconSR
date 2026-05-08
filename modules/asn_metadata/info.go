package asn_metadata

import (
	"context"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

func getASNInfo(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetASNInfo)

	dbg.Printf("getASNInfo target=%q", target)

	originASN := target
	if originASN == "" {
		errMsg := errInvalidASNFormat
		execution.Error = &errMsg
		dbg.Printf("getASNInfo target=%q invalid_format", target)
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.TimeoutASNMeta)
	defer cancel()

	var resp ripestat.ASOverviewResponse
	defer func() {
		execution.RawData = resp.RawJSON
	}()

	if err := ripestat.Query(ctx, originASN, constants.RIPEstatEndpointASOverview, &resp, resolver.MaxRetriesASNMeta); err != nil {
		errMsg := "asn info lookup failed: " + err.Error()
		execution.Error = &errMsg
		dbg.Printf("getASNInfo target=%q lookup_error=%v", target, err)
		return execution
	}

	if resp.Data.Holder != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:       constants.TypeOrganization,
			Category:   constants.CategoryNode,
			Value:      resp.Data.Holder,
			Context:    "ASN Holder",
			OutOfScope: true,
		})
	}

	dbg.Printf("getASNInfo target=%q found_holder=%q", target, resp.Data.Holder)

	return execution
}
