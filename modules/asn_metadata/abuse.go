// Package asn_metadata provides ASN intelligence gathering.
package asn_metadata

import (
	"context"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

func getASNAbuseContacts(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetASNAbuseContacts)

	dbg.Printf("getASNAbuseContacts target=%q", target)

	originASN := target
	if originASN == "" {
		errMsg := errInvalidASNFormat
		execution.Error = &errMsg
		dbg.Printf("getASNAbuseContacts target=%q invalid_format", target)
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.TimeoutASNMeta)
	defer cancel()

	var resp ripestat.AbuseContactResponse
	defer func() {
		execution.RawData = resp.RawJSON
	}()

	if err := ripestat.Query(ctx, originASN, constants.RIPEstatEndpointAbuseContactFinder, &resp, resolver.MaxRetriesASNMeta); err != nil {
		errMsg := "asn abuse lookup failed: " + err.Error()
		execution.Error = &errMsg
		dbg.Printf("getASNAbuseContacts target=%q lookup_error=%v", target, err)
		return execution
	}

	for _, contact := range resp.Data.AbuseContacts {
		if contact != "" {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:       constants.TypeEmail,
				Category:   constants.CategoryNode,
				Value:      contact,
				Context:    "Abuse Contact",
				OutOfScope: true,
			})
		}
	}

	dbg.Printf("getASNAbuseContacts target=%q found_contacts=%d", target, len(resp.Data.AbuseContacts))

	return execution
}
