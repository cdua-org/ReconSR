package dns

import (
	"context"
	"strconv"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var ipseckeyAlgorithms = map[byte]string{
	1: constants.AlgDSA,
	2: constants.AlgRSA,
	3: constants.AlgECDSA,
}

const ipsecGatewayDomainValidation = constants.TypeDomain

var ipseckeyGatewayTypes = map[byte]string{
	0: "None",
	1: "IPv4",
	2: "IPv6",
	3: "Domain",
}

func mapIPSECKEYContext(precedence, gwTypeStr, algStr string) (ctx, gwTypeName string) {
	algName := algStr
	if aNum, err := strconv.Atoi(algStr); err == nil && aNum >= 0 && aNum <= 255 {
		if name, ok := ipseckeyAlgorithms[byte(aNum)]; ok {
			algName = name
		}
	}

	gwTypeName = gwTypeStr
	if gNum, err := strconv.Atoi(gwTypeStr); err == nil && gNum >= 0 && gNum <= 255 {
		if name, ok := ipseckeyGatewayTypes[byte(gNum)]; ok {
			gwTypeName = name
		}
	}

	ctx = "IPSECKEY Record, Precedence: " + precedence + ", Alg: " + algName + ", GW Type: " + gwTypeName
	return ctx, gwTypeName
}

func classifyIPSECKEYGateway(gwTypeStr, gateway, target string, gen *modutil.LocalIDGenerator) (schema.ModuleResult, bool) {
	var validationType string

	switch gwTypeStr {
	case "1":
		validationType = constants.TypeIPv4
	case "2":
		validationType = constants.TypeIPv6
	case "3":
		validationType = ipsecGatewayDomainValidation
	default:
		return schema.ModuleResult{}, false
	}

	res, err := validator.Validate(validationType, gateway)
	if err != nil {
		return schema.ModuleResult{}, false
	}

	emittedType := res.Type
	if validationType == constants.TypeIPv4 || validationType == constants.TypeIPv6 {
		if res.Type != validationType {
			return schema.ModuleResult{}, false
		}
		emittedType = constants.TypeIP
	}

	isOOS := false
	if validationType == constants.TypeDomain {
		isOOS = orgdomain.IsOutOfScope(res.Value, target)
	}

	return schema.ModuleResult{
		Type:       emittedType,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Tags:       []string{constants.TagIPSECKEY},
		OutOfScope: isOOS,
		LocalID:    gen.NextID(),
	}, true
}

func buildIPSECKEYResults(parsed *dnsutils.IPSECKEYRecord, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) []schema.ModuleResult {
	if parsed == nil {
		return nil
	}

	_, gwTypeName := mapIPSECKEYContext(parsed.Precedence, parsed.GatewayType, parsed.Algorithm)

	results := make([]schema.ModuleResult, 0, 1)

	if parsed.Gateway == "." || parsed.Gateway == "<wire_domain>" || parsed.Gateway == "<unknown>" {
		return results
	}

	gatewayResult, ok := classifyIPSECKEYGateway(parsed.GatewayType, parsed.Gateway, target, gen)
	if !ok {
		return results
	}

	gatewayResult.Context = "IPSECKEY Gateway (" + gwTypeName + ")"
	gatewayResult.Source = source
	log.Printf("%s result_gateway target=%q entity=%q type=%q oos=%v", constants.FuncGetIPSECKEY, target, gatewayResult.Value, gatewayResult.Type, gatewayResult.OutOfScope)
	results = append(results, gatewayResult)

	return results
}

func getIPSECKEYData(ctx context.Context, target string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetIPSECKEY)
	log.Printf("%s query_start target=%q", constants.FuncGetIPSECKEY, target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 45, nil)
	if err != nil {
		log.Printf("%s error target=%q stage=resolve_record err=%v", constants.FuncGetIPSECKEY, target, err)
		modutil.SetError(&exec, "ipseckey lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		parsed := dnsutils.ParseIPSECKEY(rec)
		if parsed == nil {
			continue
		}

		ctxStr, _ := mapIPSECKEYContext(parsed.Precedence, parsed.GatewayType, parsed.Algorithm)
		ipseckeyRes := schema.ModuleResult{
			Type:     constants.TypeIPSECKEY,
			Category: constants.CategoryProperty,
			Value:    parsed.Formatted,
			Context:  ctxStr,
			LocalID:  gen.NextID(),
		}
		exec.Results = append(exec.Results, ipseckeyRes)

		source := &schema.EntityRef{Type: ipseckeyRes.Type, Value: ipseckeyRes.Value}
		exec.Results = append(exec.Results, buildIPSECKEYResults(parsed, target, source, gen)...)
	}

	log.Printf("%s success target=%q records=%d", constants.FuncGetIPSECKEY, target, len(records))
	return exec
}
