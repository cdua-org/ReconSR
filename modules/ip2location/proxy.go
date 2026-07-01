package ip2location

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func getProxyCheck(target, dbPath string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetProxyCheck)
	dbg.Printf("%s target=%q", constants.FuncGetProxyCheck, target)

	res, err := proxyQueryFunc(dbPath, target)
	if err != nil {
		errMsg := fmt.Errorf("ip2proxy error: %w", err).Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=lookup err=%v", constants.FuncGetProxyCheck, target, err)
		return execution
	}

	gen := modutil.NewLocalIDGenerator()

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	writeRaw(&rawBuffer, "IsProxy", strconv.Itoa(int(res.IsProxy)))
	if res.IsProxy == 0 {
		dbg.Printf("%s success target=%q is_proxy=0", constants.FuncGetProxyCheck, target)
		return execution
	}

	if !isUnavailable(res.ProxyType) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    mapProxyTypeToTag(res.ProxyType),
			LocalID:  gen.NextID(),
		})
		writeRaw(&rawBuffer, "ProxyType", res.ProxyType)
	}

	if !isUnavailable(res.Threat) {
		for t := range strings.SplitSeq(res.Threat, "/") {
			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:     constants.TypeTag,
				Category: constants.CategoryProperty,
				Value:    mapThreatToTag(t),
				LocalID:  gen.NextID(),
			})
		}
		writeRaw(&rawBuffer, "Threat", res.Threat)
	}

	if !isUnavailable(res.FraudScore) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeAbuseScore,
			Category: constants.CategoryProperty,
			Value:    res.FraudScore,
			Context:  "IP2Proxy Fraud Score",
			LocalID:  gen.NextID(),
		})
		writeRaw(&rawBuffer, "FraudScore", res.FraudScore)
	}

	if !isUnavailable(res.LastSeen) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Last Seen: " + res.LastSeen + " days ago",
			LocalID:  gen.NextID(),
		})
		writeRaw(&rawBuffer, "LastSeen", res.LastSeen)
	}

	if !isUnavailable(res.Provider) {
		appendInfo(&execution, "VPN/Proxy Provider", res.Provider, gen)
		writeRaw(&rawBuffer, "Provider", res.Provider)
	}

	if !isUnavailable(res.Domain) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeDomain,
			Category: constants.CategoryNode,
			Value:    res.Domain,
			Tags:     []string{constants.TagReverseIP},
			LocalID:  gen.NextID(),
		})
		writeRaw(&rawBuffer, "Domain", res.Domain)
	}

	if !isUnavailable(res.UsageType) {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeUsageType,
			Category: constants.CategoryProperty,
			Value:    ParseUsageType(res.UsageType),
			Context:  "Proxy Usage Type",
			LocalID:  gen.NextID(),
		})
		writeRaw(&rawBuffer, "UsageType", res.UsageType)
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetProxyCheck, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetProxyCheck, target)
	}

	return execution
}

func mapProxyTypeToTag(proxyType string) string {
	switch proxyType {
	case netTypeVPN:
		return constants.TagVPN
	case netTypeTOR:
		return constants.TagTorExit
	case netTypePUB, netTypeWEB:
		return constants.TagProxy
	case netTypeDCH:
		return constants.TagDataCenter
	case netTypeSES:
		return constants.TagCrawler
	case netTypeAIC:
		return constants.TagAICrawler
	case netTypeRES:
		return constants.TagResidentialProxy
	case netTypeCPN, netTypeEPN:
		return constants.TagPrivacyNetwork
	default:
		return strings.ToLower(proxyType)
	}
}

func mapThreatToTag(threat string) string {
	switch threat {
	case threatScanner:
		return constants.TagScanner
	case threatBotnet:
		return constants.TagSpamBotnet
	case threatSpam:
		return constants.TagSpam
	case threatBogon:
		return constants.TagBogon
	default:
		return strings.ToLower(threat)
	}
}
