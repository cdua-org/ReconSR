package dns

import (
	"context"
	"strconv"
	"strings"
	"time"

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

func getSOAData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_soa",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// QTYPE 6 is SOA. Standard net.Resolver does not support SOA lookups easily,
	// so we pass nil for plainFallback to rely exclusively on DoH servers for SOA.
	records, raw, err := ResolveRecord(ctx, target, 6, nil)
	if err != nil {
		errMsg := "soa lookup failed: " + err.Error()
		execution.Error = &errMsg
		return execution
	}

	if len(raw) > 0 {
		execution.RawData = string(raw)
	}

	var soa *SOA
	for _, rec := range records {
		soa = parseSOA(rec)
		if soa != nil {
			break
		}
	}

	if soa == nil {
		return execution
	}

	primaryNS := strings.TrimSuffix(soa.NS, ".")
	nsOutOfScope := !strings.HasSuffix(strings.ToLower(primaryNS), "."+strings.ToLower(target))

	responsibleEmail := formatMbox(soa.Mbox)
	var emailDomain string
	if _, after, found := strings.Cut(responsibleEmail, "@"); found {
		emailDomain = after
	}
	emailOutOfScope := emailDomain != "" && !strings.HasSuffix(strings.ToLower(emailDomain), "."+strings.ToLower(target))

	execution.Results = append(execution.Results,
		schema.ModuleResult{Type: "domain", Value: primaryNS, Context: "Primary NS", OutOfScope: nsOutOfScope},
		schema.ModuleResult{Type: "email", Value: responsibleEmail, Context: "Responsible Email", OutOfScope: emailOutOfScope},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.Serial), 10), Context: "Serial"},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.Refresh), 10), Context: "Refresh"},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.Retry), 10), Context: "Retry"},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.Expire), 10), Context: "Expire"},
		schema.ModuleResult{Type: "string", Value: strconv.FormatUint(uint64(soa.MinTTL), 10), Context: "Minimum TTL"},
	)

	return execution
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
