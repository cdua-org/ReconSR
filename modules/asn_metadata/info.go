package asn_metadata

import (
	"context"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

func getASNInfo(target string, gen *modutil.LocalIDGenerator) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetASNInfo)

	dbg.Printf("%s target=%q", constants.FuncGetASNInfo, target)

	originASN := target
	if originASN == "" {
		errMsg := errInvalidASNFormat
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=validate_input err=invalid_asn_format", constants.FuncGetASNInfo, target)
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.TimeoutASNMeta)
	defer cancel()

	var resp ripestat.ASOverviewResponse
	defer func() {
		execution.RawData = resp.RawJSON
	}()

	if err := ripestatQueryFunc(ctx, originASN, constants.RIPEstatEndpointASOverview, &resp, resolver.MaxRetriesASNMeta); err != nil {
		errMsg := "asn info lookup failed: " + err.Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=query_lookup err=%v", constants.FuncGetASNInfo, target, err)
		return execution
	}

	if resp.Data.Holder != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:       constants.TypeOrganization,
			Category:   constants.CategoryNode,
			Value:      resp.Data.Holder,
			Context:    "ASN Holder",
			OutOfScope: true,
			LocalID:    gen.NextID(),
		})
	}

	dbg.Printf("%s success target=%q found_holder=%q", constants.FuncGetASNInfo, target, resp.Data.Holder)

	return execution
}
