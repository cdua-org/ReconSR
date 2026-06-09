package virustotal

import (
	"fmt"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func (m *module) parseDNSRecord(rec map[string]any, target string, src *schema.EntityRef, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	recordType, typeOK := rec[constants.KeyType].(string)
	recordValue, valueOK := rec[constants.KeyValue].(string)
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
		m.appendVTIPRecord(exec, target, src, recordValue, gen)
	case "CNAME":
		m.appendVTCNAMEResult(exec, target, src, recordValue, gen)
	case "MX":
		m.appendVTMXResults(exec, target, src, rec, recordValue, gen)
	case "NS":
		m.appendVTNSResult(exec, target, src, recordValue, gen)
	case "SOA":
		m.appendVTSOAResults(exec, target, src, rec, gen)
	case "TXT":
		m.appendVTTXTResult(exec, target, src, recordValue, gen)
	case "CAA":
		m.appendVTCAAResults(exec, target, src, rec, gen)
	case "SRV":
		m.appendVTSRVResults(exec, target, src, rec, recordValue, gen)
	default:
		dbg.Printf("%s dns_record_fallback target=%q type=%q value=%q", constants.FuncGetVTApiDomain, target, recordType, recordValue)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     strings.ToLower(recordType),
			Category: constants.CategoryProperty,
			Value:    recordValue,
			Source:   src,
			LocalID:  gen.NextID(),
		})
	}
}

func (m *module) appendVTIPRecord(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string, gen *modutil.LocalIDGenerator) {
	validated, err := validator.Validate(constants.TypeIP, value)
	if err != nil {
		dbg.Printf("%s skip_invalid_ip target=%q value=%q err=%v", constants.FuncGetVTApiDomain, target, value, err)
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     validated.Type,
		Category: constants.CategoryNode,
		Value:    validated.Value,
		Source:   src,
		LocalID:  gen.NextID(),
	})
}

func (m *module) appendVTCNAMEResult(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string, gen *modutil.LocalIDGenerator) {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		dbg.Printf("%s skip_invalid_cname target=%q value=%q err=%v", constants.FuncGetVTApiDomain, target, value, err)
		return
	}

	if validated.Value == target {
		return
	}

	isOOS := orgdomain.IsOutOfScope(validated.Value, target)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagCNAME},
		OutOfScope: isOOS,
		Source:     src,
		LocalID:    gen.NextID(),
	})
}

func (m *module) appendVTMXResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any, value string, gen *modutil.LocalIDGenerator) {
	mxValue := value
	if priority, ok := formatVTInt(rec[constants.KeyPriority]); ok {
		mxValue = priority + " " + value
	}

	mxLocalID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeMX,
		Category: constants.CategoryProperty,
		Value:    mxValue,
		Source:   src,
		LocalID:  mxLocalID,
	})

	mxRef := &schema.EntityRef{Type: constants.TypeMX, Value: mxValue, LocalID: mxLocalID}

	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		dbg.Printf("%s skip_invalid_mx_host target=%q value=%q err=%v", constants.FuncGetVTApiDomain, target, value, err)
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
		LocalID:    gen.NextID(),
	})
}

func (m *module) appendVTNSResult(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string, gen *modutil.LocalIDGenerator) {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		dbg.Printf("%s skip_invalid_ns target=%q value=%q err=%v", constants.FuncGetVTApiDomain, target, value, err)
		return
	}

	if validated.Value == target {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagNS},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     src,
		LocalID:    gen.NextID(),
	})
}

func (m *module) appendVTSOAResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any, gen *modutil.LocalIDGenerator) {
	parts := make([]string, 0, 7)
	var rawNS, rawRname string

	if primaryNS, ok := rec[constants.KeyValue].(string); ok && strings.TrimSpace(primaryNS) != "" {
		rawNS = ensureFQDN(primaryNS)
		parts = append(parts, rawNS)
	}
	if rname, ok := rec["rname"].(string); ok && strings.TrimSpace(rname) != "" {
		rawRname = ensureFQDN(rname)
		parts = append(parts, rawRname)
	}
	for _, field := range []string{constants.KeySerial, "refresh", "retry", "expire", "minimum"} {
		if fieldValue, ok := formatVTInt(rec[field]); ok {
			parts = append(parts, fieldValue)
		}
	}
	if len(parts) == 0 {
		return
	}

	soaRaw := strings.Join(parts, " ")
	soaLocalID := gen.NextID()
	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: soaRaw, LocalID: soaLocalID}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSOA,
		Category: constants.CategoryProperty,
		Value:    soaRaw,
		Source:   src,
		LocalID:  soaLocalID,
	})

	if rawNS != "" {
		m.appendVTNSResult(exec, target, soaRef, rawNS, gen)
	}

	if rawRname != "" {
		email := dnsutils.FormatSOAMbox(rawRname)
		if validated, err := validator.Validate(constants.TypeEmail, email); err == nil {
			if validated.Value == target {
				return
			}
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validated.Type,
				Category:   constants.CategoryNode,
				Value:      validated.Value,
				Context:    "Responsible Email",
				OutOfScope: orgdomain.IsEmailOutOfScope(validated.Value, target),
				Source:     soaRef,
				LocalID:    gen.NextID(),
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

func (m *module) appendVTTXTResult(exec *schema.ModuleExecution, target string, src *schema.EntityRef, value string, gen *modutil.LocalIDGenerator) {
	resultType := constants.TypeTXT
	if strings.HasPrefix(strings.ToLower(value), "v=spf1") {
		resultType = constants.TypeSPF
	}

	txtLocalID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Source:   src,
		LocalID:  txtLocalID,
	})

	if resultType == constants.TypeSPF {
		spfRef := &schema.EntityRef{Type: constants.TypeSPF, Value: value, LocalID: txtLocalID}
		for _, ent := range dnsutils.ParseSPF(value) {
			spfResult, ok := buildVTSPFEntityResult(spfRef, ent, target, gen)
			if ok {
				exec.Results = append(exec.Results, spfResult)
			}
		}
	}
}

func buildVTSPFEntityResult(source *schema.EntityRef, ent dnsutils.SPFEntity, target string, gen *modutil.LocalIDGenerator) (schema.ModuleResult, bool) {
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
			LocalID:  gen.NextID(),
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
			LocalID:    gen.NextID(),
		}, true
	default:
		return schema.ModuleResult{}, false
	}
}

func (m *module) appendVTCAAResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any, gen *modutil.LocalIDGenerator) {
	flagValue := "0"
	if flag, ok := formatVTInt(rec[constants.KeyFlag]); ok {
		flagValue = flag
	}

	tag := ""
	if rawTag, ok := rec["tag"].(string); ok {
		tag = strings.TrimSpace(strings.ToLower(rawTag))
	}

	value := ""
	if rawValue, ok := rec[constants.KeyValue].(string); ok {
		value = strings.TrimSpace(rawValue)
	}
	if value == "" {
		return
	}

	propertyValue := value
	if tag != "" {
		propertyValue = fmt.Sprintf("%s %s %q", flagValue, tag, value)
	}

	caaLocalID := gen.NextID()
	caaRef := &schema.EntityRef{Type: constants.TypeCAA, Value: propertyValue, LocalID: caaLocalID}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeCAA,
		Category: constants.CategoryProperty,
		Value:    propertyValue,
		Source:   src,
		LocalID:  caaLocalID,
	})

	switch tag {
	case "issue", "issuewild", "issuemail":
		authority := dnsutils.ExtractCAAAuthority(value)
		if authority == "" {
			return
		}
		validated, err := validator.Validate(constants.TypeDomain, authority)
		if err != nil {
			dbg.Printf("%s skip_invalid_caa_authority authority=%q tag=%q err=%v", constants.FuncGetVTApiDomain, authority, tag, err)
			return
		}

		if validated.Value == target {
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
			LocalID:    gen.NextID(),
		})
	case constants.DNSIodef:
		email := dnsutils.ExtractCAAIodefEmail(value)
		if email == "" {
			return
		}
		validated, err := validator.Validate(constants.TypeEmail, email)
		if err != nil {
			dbg.Printf("%s skip_invalid_caa_email email=%q tag=%q err=%v", constants.FuncGetVTApiDomain, email, tag, err)
			return
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       validated.Type,
			Category:   constants.CategoryNode,
			Value:      validated.Value,
			Context:    "CAA Violation Report",
			OutOfScope: orgdomain.IsEmailOutOfScope(validated.Value, target),
			Source:     caaRef,
			LocalID:    gen.NextID(),
		})
	}
}

func (m *module) appendVTSRVResults(exec *schema.ModuleExecution, target string, src *schema.EntityRef, rec map[string]any, value string, gen *modutil.LocalIDGenerator) {
	srvValue := value
	if priority, ok := formatVTInt(rec[constants.KeyPriority]); ok {
		if !strings.HasPrefix(value, priority+" ") {
			srvValue = priority + " " + value
		}
	}

	srvLocalID := gen.NextID()
	srvRef := &schema.EntityRef{Type: constants.TypeSRV, Value: srvValue, LocalID: srvLocalID}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSRV,
		Category: constants.CategoryProperty,
		Value:    srvValue,
		Source:   src,
		LocalID:  srvLocalID,
	})

	host, err := dnsutils.ParseSRVHost(srvValue)
	if err != nil {
		dbg.Printf("%s skip_invalid_srv target=%q value=%q err=%v", constants.FuncGetVTApiDomain, target, srvValue, err)
		return
	}

	validated, err := validator.Validate(constants.TypeDomain, host)
	if err != nil {
		dbg.Printf("%s skip_invalid_srv_host target=%q host=%q err=%v", constants.FuncGetVTApiDomain, target, host, err)
		return
	}

	if validated.Value == target {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagSRV},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     srvRef,
		LocalID:    gen.NextID(),
	})
}
