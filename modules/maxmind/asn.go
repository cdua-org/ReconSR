// Package maxmind integrates local MMDB parsers to ensure low-latency intelligence aggregation without third-party API exposure.
package maxmind

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func getIPASN(target, dbPath string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetIPASN)
	dbg.Printf("%s target=%q", constants.FuncGetIPASN, target)

	ispRes, asnRes, err := asnQueryFunc(dbPath, target)
	if err != nil {
		errMsg := fmt.Errorf("maxmind asn/isp error: %w", err).Error()
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

	gen := modutil.NewLocalIDGenerator()

	var asn *ParsedASN
	var isp *ParsedISP

	if ispRes != nil {
		asn = ParseASN(ispRes)
		isp = ParseISP(ispRes)
	} else if asnRes != nil {
		asn = ParseASN(asnRes)
	}

	if isp != nil {
		if isp.ISP != "" {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeISP,
				Category: constants.CategoryProperty,
				Value:    isp.ISP,
				LocalID:  gen.NextID(),
			})
			writeRaw(&rawBuffer, "ISP", isp.ISP)
		}

		if isp.Organization != "" {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeOrganization,
				Category: constants.CategoryProperty,
				Value:    isp.Organization,
				LocalID:  gen.NextID(),
			})
			writeRaw(&rawBuffer, "Organization", isp.Organization)
		}

		if isp.MobileCountryCode != "" {
			writeRaw(&rawBuffer, "MobileCountryCode", isp.MobileCountryCode)
		}
		if isp.MobileNetworkCode != "" {
			writeRaw(&rawBuffer, "MobileNetworkCode", isp.MobileNetworkCode)
		}
	}

	if asn != nil {
		if asn.ASNOrg != "" {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeOrganization,
				Category: constants.CategoryProperty,
				Value:    asn.ASNOrg,
				Context:  "ASN Organization",
				LocalID:  gen.NextID(),
			})
			writeRaw(&rawBuffer, "AutonomousSystemOrganization", asn.ASNOrg)
		}

		if asn.ASN > 0 {
			asnVal := "AS" + strconv.FormatUint(uint64(asn.ASN), 10)
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeASN,
				Category: constants.CategoryNode,
				Value:    asnVal,
				LocalID:  gen.NextID(),
			})
			writeRaw(&rawBuffer, "AutonomousSystemNumber", asnVal)
		}
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetIPASN, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetIPASN, target)
	}

	return execution
}
