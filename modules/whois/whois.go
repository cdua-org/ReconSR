// Package whois provides parsing for WHOIS and RDAP responses.
package whois

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/debuglog"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var dbg = debuglog.New("whois")

type module struct{}

// New instantiates the WHOIS metadata module for the Dispatcher.
func New() schema.Module {
	return &module{}
}

func (m *module) Name() string {
	return "whois"
}

func (m *module) Capabilities() (schema.ModuleCapabilities, error) {
	return schema.ModuleCapabilities{
		Functions:  []string{constants.FuncGetWhois},
		InputTypes: []string{constants.TypeDomain},
		ModuleConfig: &schema.FunctionCapabilities{
			Limit:   5,
			DelayMs: 2000,
		},
	}, nil
}

func (m *module) Exec(data schema.ModuleInput) (schema.ModuleOutput, error) {
	executions := make([]schema.ModuleExecution, 0, len(data.Functions))

	for _, f := range data.Functions {
		var execution schema.ModuleExecution

		if f == constants.FuncGetWhois {
			execution = m.getWhoisData(data.Target.Value)
		} else {
			execution = modutil.NewExecution(f)
			errMsg := "unsupported function: " + f
			execution.Error = &errMsg
		}

		executions = append(executions, execution)
	}

	return schema.ModuleOutput{
		Executions: executions,
	}, nil
}

func (m *module) getWhoisData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: constants.FuncGetWhois,
		Results:  make([]schema.ModuleResult, 0, 35),
	}

	dbg.Printf("%s start target=%q", constants.FuncGetWhois, target)

	ctx := context.Background()

	var metadata Metadata
	var rawData string

	disableRDAP := false
	if val, ok := resolver.GetOption("DisableRDAP"); ok && strings.EqualFold(val, "true") {
		disableRDAP = true
	}

	methodUsed := ""

	rErr := func() error {
		if disableRDAP {
			return errors.New("RDAP disabled via configuration")
		}
		rdapData, err := queryRDAP(ctx, target)
		if err != nil {
			return fmt.Errorf("rdap failed: %w", err)
		}
		metadata = parseRDAP(rdapData)
		if rawBytes, mErr := json.Marshal(rdapData); mErr == nil {
			methodUsed = "RDAP"
			rawData = string(rawBytes)
		}
		return nil
	}()

	if rawData == "" {
		whoisRaw, wErr := queryWHOIS(ctx, target)
		if whoisRaw != "" {
			rawData = whoisRaw
			metadata = parseWHOIS(whoisRaw)
			methodUsed = "TCP 43 WHOIS"
		}
		if wErr != nil {
			errStr := ""
			if rErr != nil {
				errStr = rErr.Error() + "; "
			}
			errMsg := errStr + "whois fallback failed: " + wErr.Error()
			dbg.Printf("%s error target=%q stage=query err=%q", constants.FuncGetWhois, target, errMsg)
			execution.Error = &errMsg
			execution.RawData = rawData
			return execution
		}
	}

	dbg.Printf("%s success target=%q method=%q used_dns=%q raw_len=%d", constants.FuncGetWhois, target, methodUsed, resolver.GetLastUsedPlain(), len(rawData))
	if rawData != "" {
		sample := rawData
		if len(sample) > 300 {
			sample = sample[:300] + "..."
		}
		dbg.Printf("%s raw_sample=%q", constants.FuncGetWhois, sample)
	}

	execution.RawData = rawData
	gen := modutil.NewLocalIDGenerator()
	execution.Results = m.buildResults(&metadata, target, methodUsed, gen)

	return execution
}
