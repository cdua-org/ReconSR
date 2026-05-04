package dns

import (
	"context"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

// SOA represents the parsed SOA record data.
type SOA struct {
	NS      string
	Mbox    string
	Serial  uint32
	Refresh uint32
	Retry   uint32
	Expire  uint32
	MinTTL  uint32
}

func getSOAData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_soa")

	log.Printf("get_soa query target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 6, nil)
	if err != nil {
		log.Printf("get_soa error target=%q err=%v", target, err)
		modutil.SetError(&exec, "soa lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	var soaRaw string
	var soa *SOA
	for _, rec := range records {
		soa = parseSOA(rec)
		if soa != nil {
			soaRaw = rec
			break
		}
	}

	if soa == nil {
		return exec
	}

	exec.Results = append(exec.Results,
		schema.ModuleResult{Type: "soa", Category: "property", Value: soaRaw},
		schema.ModuleResult{Type: "soa", Category: "property", Value: strconv.FormatUint(uint64(soa.Serial), 10), Context: "Serial"},
	)

	if result := buildSOAPrimaryNSResult(soa.NS, target); result != nil {
		exec.Results = append(exec.Results, *result)
	}

	if result := buildSOAResponsibleEmailResult(soa.Mbox, target); result != nil {
		exec.Results = append(exec.Results, *result)
	}

	log.Printf("get_soa success target=%q results=%d", target, len(exec.Results))

	return exec
}

func parseSOA(data string) *SOA {
	parts := strings.Fields(data)
	if len(parts) < 7 {
		return nil
	}

	return &SOA{
		NS:      parts[0],
		Mbox:    parts[1],
		Serial:  parseUint(parts[2]),
		Refresh: parseUint(parts[3]),
		Retry:   parseUint(parts[4]),
		Expire:  parseUint(parts[5]),
		MinTTL:  parseUint(parts[6]),
	}
}

func parseUint(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(v)
}

func formatMbox(mbox string) string {
	mbox = strings.TrimSuffix(mbox, ".")
	if before, _, found := strings.Cut(mbox, "."); found {
		return before + "@" + mbox[len(before)+1:]
	}
	return mbox
}

func buildSOAPrimaryNSResult(rawNS, target string) *schema.ModuleResult {
	primaryNS := strings.TrimSuffix(rawNS, ".")
	res, err := validator.Validate("domain", primaryNS)
	if err != nil {
		log.Printf("get_soa skipping invalid primary ns target=%q entity=%q err=%v", target, primaryNS, err)
		return nil
	}

	isOOS := orgdomain.IsOutOfScope(res.Value, target)
	log.Printf("get_soa target=%q entity=%q oos=%v", target, res.Value, isOOS)

	return &schema.ModuleResult{
		Type:       "ns",
		Category:   "node",
		Value:      res.Value,
		Context:    "Primary NS",
		OutOfScope: isOOS,
	}
}

func buildSOAResponsibleEmailResult(rawMbox, target string) *schema.ModuleResult {
	responsibleEmail := formatMbox(rawMbox)
	res, err := validator.Validate("email", responsibleEmail)
	if err != nil {
		log.Printf("get_soa skipping invalid responsible email target=%q email=%q err=%v", target, responsibleEmail, err)
		return nil
	}

	isOOS := orgdomain.IsEmailOutOfScope(res.Value, target)
	log.Printf("get_soa target=%q email=%q oos=%v", target, res.Value, isOOS)

	return &schema.ModuleResult{
		Type:       res.Type,
		Category:   "node",
		Value:      res.Value,
		Context:    "Responsible Email",
		OutOfScope: isOOS,
	}
}
