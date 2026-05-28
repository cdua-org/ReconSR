package maxmind

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

// AnonymousPlusIP defines the strict mapping structure required to unmarshal the proprietary MaxMind proxy threat databases.
type AnonymousPlusIP struct {
	NetworkLastSeen      string `maxminddb:"network_last_seen"`
	ProviderName         string `maxminddb:"provider_name"`
	IsAnonymous          bool   `maxminddb:"is_anonymous"`
	IsAnonymousVPN       bool   `maxminddb:"is_anonymous_vpn"`
	IsHostingProvider    bool   `maxminddb:"is_hosting_provider"`
	IsPublicProxy        bool   `maxminddb:"is_public_proxy"`
	IsResidentialProxy   bool   `maxminddb:"is_residential_proxy"`
	IsTorExitNode        bool   `maxminddb:"is_tor_exit_node"`
	AnonymizerConfidence uint16 `maxminddb:"anonymizer_confidence"`
}

func getProxyCheck(target, dbPath string) schema.ModuleExecution {
	execution := modutil.NewExecution(constants.FuncGetProxyCheck)
	dbg.Printf("%s target=%q", constants.FuncGetProxyCheck, target)

	res, err := proxyQueryFunc(dbPath, target)
	if err != nil {
		errMsg := fmt.Errorf("maxmind proxy error: %w", err).Error()
		execution.Error = &errMsg
		dbg.Printf("%s error target=%q stage=lookup err=%v", constants.FuncGetProxyCheck, target, err)
		return execution
	}

	var rawBuffer strings.Builder
	defer func() {
		if rawBuffer.Len() > 0 {
			execution.RawData = rawBuffer.String()
		}
	}()

	if !res.IsAnonymous {
		writeRaw(&rawBuffer, "IsAnonymous", "false")
		dbg.Printf("%s success target=%q is_anonymous=false", constants.FuncGetProxyCheck, target)
		return execution
	}

	writeRaw(&rawBuffer, "IsAnonymous", "true")
	gen := modutil.NewLocalIDGenerator()

	if res.IsAnonymousVPN {
		addTagResult(&execution, constants.TagVPN, gen)
		writeRaw(&rawBuffer, "IsAnonymousVPN", "true")
	}
	if res.IsHostingProvider {
		addTagResult(&execution, constants.TagDataCenter, gen)
		writeRaw(&rawBuffer, "IsHostingProvider", "true")
	}
	if res.IsPublicProxy {
		addTagResult(&execution, constants.TagProxy, gen)
		writeRaw(&rawBuffer, "IsPublicProxy", "true")
	}
	if res.IsResidentialProxy {
		addTagResult(&execution, constants.TagResidentialProxy, gen)
		writeRaw(&rawBuffer, "IsResidentialProxy", "true")
	}
	if res.IsTorExitNode {
		addTagResult(&execution, constants.TagTorExit, gen)
		writeRaw(&rawBuffer, "IsTorExitNode", "true")
	}

	if res.AnonymizerConfidence > 0 {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeConfidenceScore,
			Category: constants.CategoryProperty,
			Value:    strconv.Itoa(int(res.AnonymizerConfidence)),
			Context:  "Anonymizer Confidence Score",
			LocalID:  gen.NextID(),
		})
		writeRaw(&rawBuffer, "AnonymizerConfidence", strconv.Itoa(int(res.AnonymizerConfidence)))
	}

	if res.ProviderName != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    res.ProviderName,
			Context:  "VPN/Proxy Provider",
			LocalID:  gen.NextID(),
		})
		writeRaw(&rawBuffer, "ProviderName", res.ProviderName)
	}

	if res.NetworkLastSeen != "" {
		execution.Results = append(execution.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Last Seen: " + res.NetworkLastSeen,
			LocalID:  gen.NextID(),
		})
		writeRaw(&rawBuffer, "NetworkLastSeen", res.NetworkLastSeen)
	}

	if len(execution.Results) > 0 {
		dbg.Printf("%s success target=%q results=%d", constants.FuncGetProxyCheck, target, len(execution.Results))
	} else {
		dbg.Printf("%s target=%q result_count=0", constants.FuncGetProxyCheck, target)
	}

	return execution
}

func addTagResult(execution *schema.ModuleExecution, tag string, gen *modutil.LocalIDGenerator) {
	execution.Results = append(execution.Results, schema.ModuleResult{
		Type:     constants.TypeTag,
		Category: constants.CategoryProperty,
		Value:    tag,
		LocalID:  gen.NextID(),
	})
}
