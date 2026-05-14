package virustotal

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func (m *module) parseDNSRecord(rec map[string]any, target string, src *schema.EntityRef, exec *schema.ModuleExecution) {
	recordType, typeOK := rec["type"].(string)
	recordValue, valueOK := rec["value"].(string)
	if !typeOK || !valueOK {
		return
	}

	recordType = strings.TrimSpace(strings.ToUpper(recordType))
	recordValue = strings.TrimSpace(recordValue)
	if recordType == "" || recordValue == "" {
		return
	}

	switch recordType {
	case "A", "AAAA":
		m.appendVTIPRecord(exec, target, src, recordValue)
	case "CNAME":
		m.appendVTCNAMEResult(exec, target, src, recordValue)
	case "MX":
		m.appendVTMXResults(exec, target, src, rec, recordValue)
	case "NS":
		m.appendVTNSResult(exec, target, src, recordValue)
	case "SOA":
		m.appendVTSOAResults(exec, target, src, rec)
	case "TXT":
		m.appendVTTXTResult(exec, src, recordValue)
	case "CAA":
		m.appendVTCAAResults(exec, src, rec)
	default:
		dbg.Printf("parseDNSRecord target=%q type=%q fallback=true value=%q", target, recordType, recordValue)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     strings.ToLower(recordType),
			Category: constants.CategoryProperty,
			Value:    recordValue,
			Source:   src,
		})
	}
}

func (m *module) appendVTIPRecord(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string) {
	validated, err := validator.Validate(constants.TypeIP, value)
	if err != nil {
		dbg.Printf("appendVTIPRecord target=%q value=%q err=%v", target, value, err)
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     validated.Type,
		Category: constants.CategoryNode,
		Value:    validated.Value,
		Source:   src,
	})
}

func (m *module) appendVTCNAMEResult(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string) {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		dbg.Printf("appendVTCNAMEResult target=%q value=%q err=%v", target, value, err)
		return
	}

	isOOS := orgdomain.IsOutOfScope(validated.Value, target)
	resultType := validated.Type
	if isOOS {
		resultType = constants.TypeCNAMETarget
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       resultType,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Context:    "CNAME Record",
		OutOfScope: isOOS,
		Source:     src,
	})
}

func (m *module) appendVTMXResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any, value string) {
	mxValue := value
	if priority, ok := formatVTInt(rec["priority"]); ok {
		mxValue = priority + " " + value
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeMX,
		Category: constants.CategoryProperty,
		Value:    mxValue,
		Source:   src,
	})

	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		dbg.Printf("appendVTMXResults target=%q value=%q err=%v", target, value, err)
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       constants.TypeDomain,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagMX},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     src,
	})
}

func (m *module) appendVTNSResult(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string) {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		dbg.Printf("appendVTNSResult target=%q value=%q err=%v", target, value, err)
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       constants.TypeNS,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Context:    "NS Record",
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     src,
	})
}

func (m *module) appendVTSOAResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any) {
	parts := make([]string, 0, 7)
	if primaryNS, ok := rec["value"].(string); ok && strings.TrimSpace(primaryNS) != "" {
		parts = append(parts, ensureFQDN(primaryNS))
	}
	if rname, ok := rec["rname"].(string); ok && strings.TrimSpace(rname) != "" {
		parts = append(parts, ensureFQDN(rname))
	}
	for _, field := range []string{"serial", "refresh", "retry", "expire", "minimum"} {
		if fieldValue, ok := formatVTInt(rec[field]); ok {
			parts = append(parts, fieldValue)
		}
	}
	if len(parts) == 0 {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSOA,
		Category: constants.CategoryProperty,
		Value:    strings.Join(parts, " "),
		Source:   src,
	})

	if primaryNS, ok := rec["value"].(string); ok {
		m.appendVTNSResult(exec, target, src, ensureFQDN(primaryNS))
	}
}

func ensureFQDN(s string) string {
	s = strings.TrimSpace(s)
	if s != "" && !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

func (m *module) appendVTTXTResult(exec *schema.ModuleExecution, src *schema.EntityRef, value string) {
	resultType := constants.TypeTXT
	if strings.HasPrefix(strings.ToLower(value), "v=spf1") {
		resultType = constants.TypeSPF
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Source:   src,
	})
}

func (m *module) appendVTCAAResults(exec *schema.ModuleExecution, src *schema.EntityRef, rec map[string]any) {
	flagValue := "0"
	if flag, ok := formatVTInt(rec["flag"]); ok {
		flagValue = flag
	}

	tag := ""
	if rawTag, ok := rec["tag"].(string); ok {
		tag = strings.TrimSpace(strings.ToLower(rawTag))
	}

	value := ""
	if rawValue, ok := rec["value"].(string); ok {
		value = strings.TrimSpace(rawValue)
	}
	if value == "" {
		return
	}

	propertyValue := value
	if tag != "" {
		propertyValue = fmt.Sprintf("%s %s %q", flagValue, tag, value)
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeCAA,
		Category: constants.CategoryProperty,
		Value:    propertyValue,
		Source:   src,
	})

	if tag != "issue" && tag != "issuewild" && tag != "issuemail" {
		return
	}

	authority := strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
	validated, err := validator.Validate(constants.TypeDomain, authority)
	if err != nil {
		dbg.Printf("appendVTCAAResults authority=%q tag=%q err=%v", authority, tag, err)
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       constants.TypeCertAuthority,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Context:    "Authorized CA (" + tag + ")",
		OutOfScope: true,
		Source:     src,
	})
}
