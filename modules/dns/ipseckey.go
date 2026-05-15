package dns

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"

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

type wireDomainDecodeResult struct {
	domain     string
	nextOffset int
	ok         bool
}

func decodeWireDomain(data []byte, offset int) wireDomainDecodeResult {
	if offset >= len(data) {
		return wireDomainDecodeResult{}
	}

	labels := make([]string, 0, 4)
	for offset < len(data) {
		labelLen := int(data[offset])
		offset++

		if labelLen == 0 {
			if len(labels) == 0 {
				return wireDomainDecodeResult{domain: ".", nextOffset: offset, ok: true}
			}
			return wireDomainDecodeResult{domain: strings.Join(labels, "."), nextOffset: offset, ok: true}
		}

		if labelLen&0xC0 != 0 || labelLen > 63 || offset+labelLen > len(data) {
			return wireDomainDecodeResult{}
		}

		labels = append(labels, string(data[offset:offset+labelLen]))
		offset += labelLen
	}

	return wireDomainDecodeResult{}
}

func parseIPSECKEY(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 3)
	if !ok {
		return raw
	}

	precedence := data[0]
	gwType := data[1]
	alg := data[2]

	var gw string
	var pubKeyBytes []byte

	offset := 3
	switch gwType {
	case 0:
		gw = "."
		pubKeyBytes = data[offset:]
	case 1:
		if len(data) < offset+4 {
			return raw
		}
		gw = net.IP(data[offset : offset+4]).String()
		pubKeyBytes = data[offset+4:]
	case 2:
		if len(data) < offset+16 {
			return raw
		}
		gw = net.IP(data[offset : offset+16]).String()
		pubKeyBytes = data[offset+16:]
	case 3:
		decodedDomain := decodeWireDomain(data, offset)
		if !decodedDomain.ok {
			return raw
		}
		gw = decodedDomain.domain
		pubKeyBytes = data[decodedDomain.nextOffset:]
	default:
		gw = "<unknown>"
		pubKeyBytes = data[offset:]
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	return fmt.Sprintf("%d %d %d %s %s", precedence, gwType, alg, gw, pubKeyBase64)
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

func classifyIPSECKEYGateway(gwTypeStr, gateway, target string) (schema.ModuleResult, bool) {
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
	}, true
}

func buildIPSECKEYResults(parsed, target string) []schema.ModuleResult {
	parts := strings.Fields(parsed)
	if len(parts) < 5 {
		return nil
	}

	precedence := parts[0]
	gwTypeStr := parts[1]
	algStr := parts[2]
	gateway := parts[3]
	pubKey := strings.Join(parts[4:], "")

	ctxStr, gwTypeName := mapIPSECKEYContext(precedence, gwTypeStr, algStr)
	results := make([]schema.ModuleResult, 0, 2)
	results = append(results, schema.ModuleResult{
		Type:     constants.TypeIPSECKEY,
		Category: constants.CategoryProperty,
		Value:    pubKey,
		Context:  ctxStr,
	})

	if gateway == "." || gateway == "<wire_domain>" || gateway == "<unknown>" {
		return results
	}

	gatewayResult, ok := classifyIPSECKEYGateway(gwTypeStr, gateway, target)
	if !ok {
		return results
	}

	gatewayResult.Context = "IPSECKEY Gateway (" + gwTypeName + ")"
	results = append(results, gatewayResult)

	return results
}

func getIPSECKEYData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetIPSECKEY)
	log.Printf("get_ipseckey target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 45, nil)
	if err != nil {
		log.Printf("get_ipseckey error: %v", err)
		modutil.SetError(&exec, "ipseckey lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	for _, rec := range records {
		exec.Results = append(exec.Results, buildIPSECKEYResults(parseIPSECKEY(rec), target)...)
	}

	log.Printf("get_ipseckey target=%q records=%d", target, len(records))
	return exec
}
