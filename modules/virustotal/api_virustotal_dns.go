package virustotal

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
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
		m.appendVTTXTResult(exec, target, src, recordValue)
	case "CAA":
		m.appendVTCAAResults(exec, target, src, rec)
	case "SRV":
		m.appendVTSRVResults(exec, target, src, rec, recordValue)
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

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagCNAME},
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

	mxRef := &schema.EntityRef{Type: constants.TypeMX, Value: mxValue}

	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		dbg.Printf("appendVTMXResults target=%q value=%q err=%v", target, value, err)
		return
	}

	if validated.Value == target {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagMX},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     mxRef,
	})
}

func (m *module) appendVTNSResult(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string) {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		dbg.Printf("appendVTNSResult target=%q value=%q err=%v", target, value, err)
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagNS},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     src,
	})
}

func (m *module) appendVTSOAResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any) {
	parts := make([]string, 0, 7)
	var rawNS, rawRname string

	if primaryNS, ok := rec["value"].(string); ok && strings.TrimSpace(primaryNS) != "" {
		rawNS = ensureFQDN(primaryNS)
		parts = append(parts, rawNS)
	}
	if rname, ok := rec["rname"].(string); ok && strings.TrimSpace(rname) != "" {
		rawRname = ensureFQDN(rname)
		parts = append(parts, rawRname)
	}
	for _, field := range []string{"serial", "refresh", "retry", "expire", "minimum"} {
		if fieldValue, ok := formatVTInt(rec[field]); ok {
			parts = append(parts, fieldValue)
		}
	}
	if len(parts) == 0 {
		return
	}

	soaRaw := strings.Join(parts, " ")
	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: soaRaw}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSOA,
		Category: constants.CategoryProperty,
		Value:    soaRaw,
		Source:   src,
	})

	if rawNS != "" {
		m.appendVTNSResult(exec, target, soaRef, rawNS)
	}

	if rawRname != "" {
		email := dnsutils.FormatSOAMbox(rawRname)
		if validated, err := validator.Validate(constants.TypeEmail, email); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validated.Type,
				Category:   constants.CategoryNode,
				Value:      validated.Value,
				Context:    "Responsible Email",
				OutOfScope: orgdomain.IsEmailOutOfScope(validated.Value, target),
				Source:     soaRef,
			})
		}
	}
}

func ensureFQDN(s string) string {
	s = strings.TrimSpace(s)
	if s != "" && !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

func (m *module) appendVTTXTResult(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string) {
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

	if resultType == constants.TypeSPF {
		spfRef := &schema.EntityRef{Type: constants.TypeSPF, Value: value}
		for _, ent := range dnsutils.ParseSPF(value) {
			spfResult, ok := buildVTSPFEntityResult(spfRef, ent, target)
			if ok {
				exec.Results = append(exec.Results, spfResult)
			}
		}
	}
}

func buildVTSPFEntityResult(source *schema.EntityRef, ent dnsutils.SPFEntity, target string) (schema.ModuleResult, bool) {
	switch ent.Kind {
	case dnsutils.SPFEntityIP4, dnsutils.SPFEntityIP6:
		validated, err := validator.Validate(constants.TypeIP, ent.Value)
		if err != nil {
			return schema.ModuleResult{}, false
		}
		return schema.ModuleResult{
			Type:     validated.Type,
			Category: constants.CategoryNode,
			Value:    validated.Value,
			Tags:     []string{constants.TagSPF},
			Context:  "SPF " + ent.Mechanism,
			Source:   source,
		}, true
	case dnsutils.SPFEntityDomain:
		validated, err := validator.Validate(constants.TypeDomain, ent.Value)
		if err != nil {
			return schema.ModuleResult{}, false
		}
		if validated.Value == target {
			return schema.ModuleResult{}, false
		}
		return schema.ModuleResult{
			Type:       validated.Type,
			Category:   constants.CategoryNode,
			Value:      validated.Value,
			Tags:       []string{constants.TagSPF},
			Context:    "SPF " + ent.Mechanism,
			OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
			Source:     source,
		}, true
	default:
		return schema.ModuleResult{}, false
	}
}

func (m *module) appendVTCAAResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any) {
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

	caaRef := &schema.EntityRef{Type: constants.TypeCAA, Value: propertyValue}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeCAA,
		Category: constants.CategoryProperty,
		Value:    propertyValue,
		Source:   src,
	})

	switch tag {
	case "issue", "issuewild", "issuemail":
		authority := dnsutils.ExtractCAAAuthority(value)
		if authority == "" {
			return
		}
		validated, err := validator.Validate(constants.TypeDomain, authority)
		if err != nil {
			dbg.Printf("appendVTCAAResults authority=%q tag=%q err=%v", authority, tag, err)
			return
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       validated.Type,
			Category:   constants.CategoryNode,
			Value:      validated.Value,
			Tags:       []string{constants.TagCAA},
			Context:    "Authorized CA (" + tag + ")",
			OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
			Source:     caaRef,
		})
	case "iodef":
		email := dnsutils.ExtractCAAIodefEmail(value)
		if email == "" {
			return
		}
		validated, err := validator.Validate(constants.TypeEmail, email)
		if err != nil {
			dbg.Printf("appendVTCAAResults email=%q tag=%q err=%v", email, tag, err)
			return
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       validated.Type,
			Category:   constants.CategoryNode,
			Value:      validated.Value,
			Context:    "CAA Violation Report",
			OutOfScope: orgdomain.IsEmailOutOfScope(validated.Value, target),
			Source:     caaRef,
		})
	}
}

func (m *module) appendVTSRVResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any, value string) {
	srvValue := value
	if priority, ok := formatVTInt(rec["priority"]); ok {
		if !strings.HasPrefix(value, priority+" ") {
			srvValue = priority + " " + value
		}
	}

	srvRef := &schema.EntityRef{Type: constants.TypeSRV, Value: srvValue}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSRV,
		Category: constants.CategoryProperty,
		Value:    srvValue,
		Source:   src,
	})

	host, err := dnsutils.ParseSRVHost(srvValue)
	if err != nil {
		dbg.Printf("appendVTSRVResults target=%q err=%v", target, err)
		return
	}

	validated, err := validator.Validate(constants.TypeDomain, host)
	if err != nil {
		dbg.Printf("appendVTSRVResults target=%q host=%q err=%v", target, host, err)
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagSRV},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     srvRef,
	})
}
