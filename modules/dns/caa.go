package dns

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

var caaRegex = regexp.MustCompile(`(?i)^\d+\s+(issue|issuewild|iodef|issuemail)\s+"(.*)"$`)

func getCAAData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetCAA)

	log.Printf("get_caa target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSFallbackTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 257, nil)
	if err != nil {
		log.Printf("get_caa error: %v", err)
		modutil.SetError(&exec, "caa lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	log.Printf("get_caa target=%q records=%d", target, len(records))

	for _, rec := range records {
		results := parseCAARecord(rec)
		exec.Results = append(exec.Results, results...)
	}

	return exec
}

func parseCAARecord(data string) []schema.ModuleResult {
	if strings.HasPrefix(data, "\\#") {
		if decoded, err := decodeHexCAA(data); err == nil {
			data = decoded
		}
	}

	results := make([]schema.ModuleResult, 0, 2)
	results = append(results, schema.ModuleResult{
		Type:     constants.TypeCAA,
		Category: constants.CategoryProperty,
		Value:    data,
	})

	matches := caaRegex.FindStringSubmatch(data)
	if len(matches) < 3 {
		return results
	}

	tag := strings.ToLower(strings.TrimSpace(matches[1]))
	val := strings.TrimSpace(matches[2])

	switch tag {
	case "issue", "issuewild", "issuemail":
		result, ok := buildCAAAuthorityResult(tag, val)
		if ok {
			results = append(results, result)
		}
	case "iodef":
		result, ok := buildCAAIodefEmailResult(val)
		if ok {
			results = append(results, result)
		}
	}

	return results
}

func buildCAAAuthorityResult(tag, val string) (schema.ModuleResult, bool) {
	parts := strings.SplitN(val, ";", 2)
	domain := strings.TrimSpace(parts[0])
	if domain == "" {
		return schema.ModuleResult{}, false
	}

	res, err := validator.Validate(constants.TypeDomain, domain)
	if err != nil {
		log.Printf("get_caa skipping invalid authority tag=%q entity=%q err=%v", tag, domain, err)
		return schema.ModuleResult{}, false
	}

	return schema.ModuleResult{
		Type:       constants.TypeCertAuthority,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Context:    "Authorized CA" + " (" + tag + ")",
		OutOfScope: true,
	}, true
}

func buildCAAIodefEmailResult(val string) (schema.ModuleResult, bool) {
	if len(val) < len("mailto:") || !strings.EqualFold(val[:len("mailto:")], "mailto:") {
		return schema.ModuleResult{}, false
	}

	email := strings.TrimSpace(strings.TrimPrefix(val[len("mailto:"):], "//"))
	if email == "" {
		return schema.ModuleResult{}, false
	}

	res, err := validator.Validate(constants.TypeEmail, email)
	if err != nil {
		log.Printf("get_caa skipping invalid iodef email entity=%q err=%v", email, err)
		return schema.ModuleResult{}, false
	}

	return schema.ModuleResult{
		Type:       res.Type,
		Category:   constants.CategoryNode,
		Value:      res.Value,
		Context:    "CAA Violation Report",
		OutOfScope: true,
	}, true
}

func decodeHexCAA(raw string) (string, error) {
	data, ok := dnsutils.DecodeWireFormat(raw, 2)
	if !ok {
		return "", errors.New("invalid or too short CAA wire format")
	}

	flags := data[0]
	tagLen := int(data[1])
	if len(data) < 2+tagLen {
		return "", errors.New("tag length mismatch")
	}

	tag := string(data[2 : 2+tagLen])
	value := string(data[2+tagLen:])

	return strconv.Itoa(int(flags)) + " " + tag + " \"" + value + "\"", nil
}
