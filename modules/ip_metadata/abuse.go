package ip_metadata

import (
	"context"
	"fmt"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

func getIPAbuseContacts(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetIPAbuseContacts)
	gen := modutil.NewLocalIDGenerator()

	dbg.Printf("%s target=%q", constants.FuncGetIPAbuseContacts, target)

	if target == "" {
		errMsg := errInvalidIPFormat + target
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=validate_input reason=invalid_format", constants.FuncGetIPAbuseContacts, target)
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	var resp ripestat.AbuseContactResponse
	defer func() {
		execution.RawData = resp.RawJSON
	}()

	if err := ripestatQueryFunc(ctx, target, "abuse-contact-finder", &resp, resolver.MaxRetriesIPMeta); err != nil {
		errMsg := fmt.Errorf("ip abuse lookup failed after retries: %w", err).Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=lookup err=%v", constants.FuncGetIPAbuseContacts, target, err)
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
				LocalID:    gen.NextID(),
			})
		}
	}

	if len(resp.Data.AbuseContacts) > 0 {
		dbg.Printf("%s success target=%q found_contacts=%d", constants.FuncGetIPAbuseContacts, target, len(resp.Data.AbuseContacts))
	} else {
		dbg.Printf("%s target=%q found_contacts=0", constants.FuncGetIPAbuseContacts, target)
	}

	return execution
}
