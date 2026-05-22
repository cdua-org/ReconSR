package ip_metadata

import (
	"context"
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/modules/utils/ripestat"
	"cdua-org/ReconSR/schema"
)

func getIPInfo(target string) (execution schema.ModuleExecution) {
	execution = modutil.NewExecution(constants.FuncGetIPInfo)
	gen := modutil.NewLocalIDGenerator()
	dbg.Printf("%s target=%q", constants.FuncGetIPInfo, target)

	if target == "" {
		errMsg := errInvalidIPFormat + target
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=validate_input reason=invalid_format", constants.FuncGetIPInfo, target)
		return execution
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.HTTPTimeout)
	defer cancel()

	var resp ripestat.WhoisResponse
	defer func() {
		execution.RawData = resp.RawJSON
	}()

	if err := ripestatQueryFunc(ctx, target, "whois", &resp, resolver.MaxRetriesIPMeta); err != nil {
		errMsg := fmt.Errorf("ip info lookup failed after retries: %w", err).Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=lookup err=%v", constants.FuncGetIPInfo, target, err)
		return execution
	}

	var netname string
	var descr []string

	for _, records := range resp.Data.Records {
		for _, record := range records {
			key := strings.ToLower(record.Key)
			if key == constants.TypeNetName && netname == "" {
				netname = strings.TrimSpace(record.Value)
			} else if key == "descr" {
				val := strings.TrimSpace(record.Value)
				if val != "" {
					descr = append(descr, val)
				}
			}
		}
	}

	if netname != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:       constants.TypeNetName,
			Category:   constants.CategoryProperty,
			Value:      netname,
			Context:    "Network Name",
			OutOfScope: true,
			LocalID:    gen.NextID(),
		})
	}

	if len(descr) > 0 {
		description := strings.Join(descr, " | ")
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:       constants.TypeDescription,
			Category:   constants.CategoryProperty,
			Value:      description,
			Context:    "Network Description",
			OutOfScope: true,
			LocalID:    gen.NextID(),
		})
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q result_count=%d netname=%q", constants.FuncGetIPInfo, target, len(execution.Results), netname)
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetIPInfo, target)
	}

	return execution
}
