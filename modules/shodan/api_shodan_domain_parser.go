package shodan

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func parseShodanAPIDomain(exec *schema.ModuleExecution, rawBody []byte, target string) {
	var payload shodanDomainResponse
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		modutil.SetError(exec, "unmarshal json: %v", err)
		return
	}

	appendShodanTagResults(exec, payload.Tags)

	for _, record := range payload.Data {
		processShodanDomainRecord(exec, record, target)
	}
}

func processShodanDomainRecord(exec *schema.ModuleExecution, record shodanDomainRecord, target string) {
	fqdn, entityType, wildcardContext, isValidNode, ok := buildShodanFQDN(target, record.Subdomain)
	if !ok {
		return
	}

	var source *schema.EntityRef
	if isValidNode {
		if record.Type != "TXT" || !strings.HasPrefix(record.Subdomain, "_") {
			source = appendShodanSubdomain(exec, fqdn, entityType, target, wildcardContext)
		}
	}
	value := strings.TrimSpace(record.Value)
	if value == "" {
		return
	}

	lastSeenSource := processShodanDNSRecord(exec, record, value, target, source)
	appendShodanLastSeen(exec, record.LastSeen, lastSeenSource, fqdn)
}

func buildShodanFQDN(target, subdomain string) (resultValue, resultType, wildcardContext string, isValidNode, ok bool) {
	fqdn := target
	if subdomain != "" && subdomain != "@" {
		fqdn = subdomain + "." + target
	}

	isWildcard := strings.HasPrefix(fqdn, "*.")
	validatedValue := strings.TrimPrefix(fqdn, "*.")

	isValidNode = true
	validated, err := validator.Validate(constants.TypeDomain, validatedValue)
	if err != nil {
		if strings.Contains(validatedValue, "_") {
			resultValue = strings.ToLower(validatedValue)
			resultType = constants.TypeSubdomain
			isValidNode = false
		} else {
			return "", "", "", false, false
		}
	} else {
		resultValue = validated.Value
		resultType = validated.Type
	}

	if isWildcard {
		wildcardContext = "*." + resultValue
	}

	return resultValue, resultType, wildcardContext, isValidNode, true
}

func appendShodanSubdomain(exec *schema.ModuleExecution, fqdn, entityType, target, wildcardContext string) *schema.EntityRef {
	if fqdn == target && wildcardContext == "" {
		return nil
	}

	result := schema.ModuleResult{
		Type:       entityType,
		Category:   constants.CategoryNode,
		Value:      fqdn,
		Context:    "Shodan DNS",
		OutOfScope: orgdomain.IsOutOfScope(fqdn, target),
	}
	if wildcardContext != "" {
		result.Tags = []string{constants.TagWildcard}
		result.Context = wildcardContext
	}

	exec.Results = append(exec.Results, result)

	return &schema.EntityRef{Type: entityType, Value: fqdn}
}

func processShodanDNSRecord(exec *schema.ModuleExecution, record shodanDomainRecord, value, target string, source *schema.EntityRef) *schema.EntityRef {
	switch record.Type {
	case "A", "AAAA":
		return appendShodanIPResult(exec, value, source)
	case "CNAME":
		return appendShodanCNAMEResult(exec, value, target, source)
	case "MX":
		return appendShodanMXResult(exec, record, value, target, source)
	case "NS":
		return appendShodanNSResult(exec, value, target, source)
	case "SOA":
		return appendShodanSOAResults(exec, record, value, target, source)
	case "TXT":
		return appendShodanTXTResult(exec, record, value, target, source)
	case "SRV":
		return appendShodanSRVResult(exec, value, target, source)
	case "CAA":
		return appendShodanCAAResult(exec, value, target, source)
	case "URI":
		return appendShodanURIResult(exec, value, target, source)
	case "NAPTR":
		return appendShodanNAPTRResult(exec, value, target, source)
	case "RP":
		return appendShodanRPResult(exec, value, target, source)
	case "HIP":
		return appendShodanHIPResult(exec, value, target, source)
	default:
		return appendShodanGenericDNSResult(exec, record.Type, value, source)
	}
}

func appendShodanIPResult(exec *schema.ModuleExecution, value string, source *schema.EntityRef) *schema.EntityRef {
	validated, err := validator.Validate(constants.TypeIP, value)
	if err != nil {
		return nil
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     validated.Type,
		Category: constants.CategoryNode,
		Value:    validated.Value,
		Context:  "A/AAAA Record",
		Source:   source,
	})

	return &schema.EntityRef{Type: validated.Type, Value: validated.Value}
}

func appendShodanCNAMEResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef) *schema.EntityRef {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		return nil
	}

	isOOS := orgdomain.IsOutOfScope(validated.Value, target)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagCNAME},
		Context:    "CNAME Record",
		OutOfScope: isOOS,
		Source:     source,
	})

	return &schema.EntityRef{Type: validated.Type, Value: validated.Value}
}

func appendShodanMXResult(exec *schema.ModuleExecution, record shodanDomainRecord, value, target string, source *schema.EntityRef) *schema.EntityRef {
	mxValue := value
	if record.Options != nil {
		mxValue = strconv.FormatUint(uint64(record.Options.Priority), 10) + " " + value
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeMX,
		Category: constants.CategoryProperty,
		Value:    mxValue,
		Source:   source,
	})

	mxRef := &schema.EntityRef{Type: constants.TypeMX, Value: mxValue}

	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		return mxRef
	}

	if validated.Value == target {
		return mxRef
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagMX},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     mxRef,
	})

	return mxRef
}

func appendShodanNSResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef) *schema.EntityRef {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		return nil
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagNS},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     source,
	})

	return &schema.EntityRef{Type: validated.Type, Value: validated.Value}
}

func appendShodanTXTResult(exec *schema.ModuleExecution, record shodanDomainRecord, value, target string, source *schema.EntityRef) *schema.EntityRef {
	resultType := constants.TypeTXT
	contextStr := ""

	switch {
	case strings.HasPrefix(strings.ToLower(value), "v=spf1"):
		resultType = constants.TypeSPF
	case strings.EqualFold(record.Subdomain, "_dmarc"):
		resultType = constants.TypeDMARC
	case strings.HasSuffix(strings.ToLower(record.Subdomain), "_domainkey"):
		resultType = constants.TypeDKIM
	}

	if strings.HasPrefix(record.Subdomain, "_") {
		contextStr = record.Subdomain
	}

	ref := &schema.EntityRef{Type: resultType, Value: value}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Context:  contextStr,
		Source:   source,
	})

	if resultType == constants.TypeDMARC {
		parsed := dnsutils.ParseDMARC(value)
		for _, key := range []string{"ruf", "rua"} {
			val, ok := parsed[key]
			if !ok {
				continue
			}
			emails := dnsutils.ExtractDMARCEmails(val)
			for i, email := range emails {
				validatedEmail, err := validator.Validate(constants.TypeEmail, email)
				if err != nil {
					continue
				}

				isOOS := orgdomain.IsEmailOutOfScope(validatedEmail.Value, target)

				contextMsg := "DMARC " + strings.ToUpper(key)
				if len(emails) > 1 {
					contextMsg = fmt.Sprintf("DMARC %s #%d", strings.ToUpper(key), i+1)
				}

				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:       validatedEmail.Type,
					Category:   constants.CategoryNode,
					Value:      validatedEmail.Value,
					Context:    contextMsg,
					OutOfScope: isOOS,
					Source:     ref,
				})
			}
		}
	}

	return ref
}

func appendShodanSOAResults(exec *schema.ModuleExecution, record shodanDomainRecord, primaryNS, target string, source *schema.EntityRef) *schema.EntityRef {
	soaRaw := buildShodanSOARaw(primaryNS, record.Options)
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSOA,
		Category: constants.CategoryProperty,
		Value:    soaRaw,
		Source:   source,
	})

	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: soaRaw}

	if record.Options != nil && record.Options.Serial != 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeSOA,
			Category: constants.CategoryProperty,
			Value:    strconv.FormatUint(record.Options.Serial, 10),
			Context:  "Serial",
			Source:   soaRef,
		})
	}

	validatedNS, err := validator.Validate(constants.TypeDomain, primaryNS)
	if err == nil {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       validatedNS.Type,
			Category:   constants.CategoryNode,
			Value:      validatedNS.Value,
			Tags:       []string{constants.TagNS},
			Context:    "Primary NS",
			OutOfScope: orgdomain.IsOutOfScope(validatedNS.Value, target),
			Source:     soaRef,
		})
	}

	if record.Options != nil && record.Options.Hostmaster != "" {
		email := dnsutils.FormatSOAMbox(record.Options.Hostmaster)
		validatedEmail, emailErr := validator.Validate(constants.TypeEmail, email)
		if emailErr == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validatedEmail.Type,
				Category:   constants.CategoryNode,
				Value:      validatedEmail.Value,
				Context:    "Responsible Email",
				OutOfScope: orgdomain.IsEmailOutOfScope(validatedEmail.Value, target),
				Source:     soaRef,
			})
		}
	}

	return soaRef
}

func buildShodanSOARaw(primaryNS string, opts *shodanDomainRecordOptions) string {
	if !strings.HasSuffix(primaryNS, ".") {
		primaryNS += "."
	}
	if opts == nil {
		return primaryNS
	}

	hostmaster := opts.Hostmaster
	if hostmaster != "" && !strings.HasSuffix(hostmaster, ".") {
		hostmaster += "."
	}

	return fmt.Sprintf("%s %s %d %d %d %d %d",
		primaryNS, hostmaster,
		opts.Serial, opts.Refresh, opts.Retry, opts.Expires, opts.MinTTL)
}

func appendShodanGenericDNSResult(exec *schema.ModuleExecution, recordType, value string, source *schema.EntityRef) *schema.EntityRef {
	resultType := strings.ToLower(recordType)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Source:   source,
	})

	return &schema.EntityRef{Type: resultType, Value: value}
}

func appendShodanLastSeen(exec *schema.ModuleExecution, lastSeen string, source *schema.EntityRef, fqdn string) {
	lastSeen = strings.TrimSpace(lastSeen)
	if lastSeen == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeLastSeen,
		Category: constants.CategoryProperty,
		Value:    lastSeen,
		Context:  fqdn,
		Source:   source,
	})
}

func appendShodanSRVResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef) *schema.EntityRef {
	ref := appendShodanGenericDNSResult(exec, "SRV", value, source)
	if host, err := dnsutils.ParseSRVHost(value); err == nil {
		if validated, err := validator.Validate(constants.TypeDomain, host); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validated.Type,
				Category:   constants.CategoryNode,
				Value:      validated.Value,
				Tags:       []string{constants.TagSRV},
				OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
				Source:     ref,
			})
		}
	}
	return ref
}

func appendShodanCAAResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef) *schema.EntityRef {
	normalized, tag, parsedVal, matched := dnsutils.ParseCAA(value)
	ref := appendShodanGenericDNSResult(exec, "CAA", normalized, source)

	if !matched {
		return ref
	}

	switch tag {
	case "issue", "issuewild", "issuemail":
		domain := dnsutils.ExtractCAAAuthority(parsedVal)
		if domain != "" {
			if validated, err := validator.Validate(constants.TypeDomain, domain); err == nil {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:       validated.Type,
					Category:   constants.CategoryNode,
					Value:      validated.Value,
					Tags:       []string{constants.TagCAA},
					Context:    "Authorized CA (" + tag + ")",
					OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
					Source:     ref,
				})
			}
		}
	case "iodef":
		email := dnsutils.ExtractCAAIodefEmail(parsedVal)
		if email != "" {
			if validated, err := validator.Validate(constants.TypeEmail, email); err == nil {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:       validated.Type,
					Category:   constants.CategoryNode,
					Value:      validated.Value,
					Context:    "CAA Violation Report",
					OutOfScope: orgdomain.IsEmailOutOfScope(validated.Value, target),
					Source:     ref,
				})
			}
		}
	}

	return ref
}

func appendShodanURIResult(exec *schema.ModuleExecution, value, _ string, source *schema.EntityRef) *schema.EntityRef {
	parsed := dnsutils.ParseURI(value)
	if parsed == nil {
		return appendShodanGenericDNSResult(exec, "URI", value, source)
	}

	ref := appendShodanGenericDNSResult(exec, "URI", parsed.Formatted, source)

	if parsed.Target != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeURL,
			Category: constants.CategoryProperty,
			Value:    parsed.Target,
			Context:  "URI Endpoint",
			Source:   ref,
		})
	}

	return ref
}

func appendShodanNAPTRResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef) *schema.EntityRef {
	parsed := dnsutils.ParseNAPTR(value)
	if parsed == nil {
		return appendShodanGenericDNSResult(exec, "NAPTR", value, source)
	}

	ref := appendShodanGenericDNSResult(exec, "NAPTR", parsed.Formatted, source)

	targetSource := ref
	if parsed.Service != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeNAPTR,
			Category: constants.CategoryProperty,
			Value:    parsed.Service,
			Context:  "NAPTR Service",
			Source:   ref,
		})
		targetSource = &schema.EntityRef{Type: constants.TypeNAPTR, Value: parsed.Service}
	}

	if parsed.Regexp != "" {
		regexpSource := targetSource
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeNAPTR,
			Category: constants.CategoryProperty,
			Value:    parsed.Regexp,
			Context:  "NAPTR Regexp",
			Source:   regexpSource,
		})
		if parsed.RegexpTarget != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeURL,
				Category: constants.CategoryProperty,
				Value:    parsed.RegexpTarget,
				Context:  "NAPTR Regexp Target",
				Source:   &schema.EntityRef{Type: constants.TypeNAPTR, Value: parsed.Regexp},
			})
		}
	}

	if parsed.Replacement != "" {
		targetNode := dnsutils.CleanSRVTarget(parsed.Replacement)
		validatedValue := targetNode
		validatedType := constants.TypeSubdomain
		valid := false

		if validated, err := validator.Validate(constants.TypeDomain, targetNode); err == nil {
			validatedValue = validated.Value
			validatedType = validated.Type
			valid = true
		}

		if valid && validatedValue != target {
			contextStr := "NAPTR Target"
			if parsed.Replacement != validatedValue && parsed.Replacement != validatedValue+"." {
				contextStr = "NAPTR Target (" + parsed.Replacement + ")"
			}

			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validatedType,
				Category:   constants.CategoryNode,
				Value:      validatedValue,
				Tags:       []string{constants.TagNAPTR},
				Context:    contextStr,
				OutOfScope: orgdomain.IsOutOfScope(validatedValue, target),
				Source:     targetSource,
			})
		}
	}
	return ref
}

func appendShodanRPResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef) *schema.EntityRef {
	ref := appendShodanGenericDNSResult(exec, "RP", value, source)
	parts := strings.Fields(value)
	if len(parts) >= 2 {
		mbox := strings.TrimSuffix(parts[0], ".")
		if idx := strings.Index(mbox, "."); idx > 0 && idx < len(mbox)-1 {
			mbox = mbox[:idx] + "@" + mbox[idx+1:]
		}
		if validated, err := validator.Validate(constants.TypeEmail, mbox); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validated.Type,
				Category:   constants.CategoryNode,
				Value:      validated.Value,
				Context:    "RP Administrator Email",
				OutOfScope: orgdomain.IsEmailOutOfScope(validated.Value, target),
				Source:     ref,
			})
		}

		txtDomain := strings.TrimSuffix(parts[1], ".")
		if validated, err := validator.Validate(constants.TypeDomain, txtDomain); err == nil {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validated.Type,
				Category:   constants.CategoryNode,
				Value:      validated.Value,
				Tags:       []string{constants.TagRP},
				Context:    "RP TXT Reference Domain",
				OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
				Source:     ref,
			})
		}
	}
	return ref
}

func appendShodanHIPResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef) *schema.EntityRef {
	ref := appendShodanGenericDNSResult(exec, "HIP", value, source)
	parts := strings.Fields(value)
	if len(parts) >= 4 {
		for _, rv := range parts[3:] {
			rvNode := strings.TrimSuffix(rv, ".")
			if validated, err := validator.Validate(constants.TypeDomain, rvNode); err == nil {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:       validated.Type,
					Category:   constants.CategoryNode,
					Value:      validated.Value,
					Tags:       []string{constants.TagHIP},
					Context:    "HIP Rendezvous Server",
					OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
					Source:     ref,
				})
			}
		}
	}
	return ref
}
