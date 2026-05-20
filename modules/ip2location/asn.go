package ip2location

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func getIPASN(target, dbPath string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetIPASN)
	dbg.Printf("%s target=%q", constants.FuncGetIPASN, target)

	res, err := asnQueryFunc(dbPath, target)
	if err != nil {
		errMsg := fmt.Errorf("ip2location asn error: %w", err).Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=lookup err=%v", constants.FuncGetIPASN, target, err)
		return execution
	}

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	if !isUnavailable(res.Asn) {
		val := res.Asn
		if !strings.HasPrefix(strings.ToUpper(val), "AS") {
			val = "AS" + val
		}

		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeASN,
			Category: constants.CategoryNode,
			Value:    val,
		})
		writeRaw(&rawBuffer, "Asn", res.Asn)
	}

	if !isUnavailable(res.As) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeOrganization,
			Category: constants.CategoryProperty,
			Value:    res.As,
			Context:  "AS Owner",
		})
		writeRaw(&rawBuffer, "As", res.As)
	}

	if !isUnavailable(res.Asdomain) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeDomain,
			Category: constants.CategoryNode,
			Value:    res.Asdomain,
			Tags:     []string{constants.TagLinked},
		})
		writeRaw(&rawBuffer, "Asdomain", res.Asdomain)
	}

	if !isUnavailable(res.Asusagetype) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeUsageType,
			Category: constants.CategoryProperty,
			Value:    ParseUsageType(res.Asusagetype),
			Context:  "AS Usage Type",
		})
		writeRaw(&rawBuffer, "Asusagetype", res.Asusagetype)
	}

	if !isUnavailable(res.Ascidr) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeCIDR,
			Category: constants.CategoryProperty,
			Value:    res.Ascidr,
			Context:  "AS CIDR",
		})
		writeRaw(&rawBuffer, "Ascidr", res.Ascidr)
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetIPASN, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetIPASN, target)
	}

	return execution
}
