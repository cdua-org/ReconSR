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
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func parseShodanAPIDomain(exec *schema.ModuleExecution, rawBody []byte, target string) {
	var payload shodanDomainResponse
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		modutil.SetError(exec, "unmarshal json: %v", err)
		return
	}

	gen := modutil.NewLocalIDGenerator()
	appendShodanTagResults(exec, payload.Tags, gen)

	for _, record := range payload.Data {
		processShodanDomainRecord(exec, record, target, gen)
	}
}

func processShodanDomainRecord(exec *schema.ModuleExecution, record shodanDomainRecord, target string, gen *modutil.LocalIDGenerator) {
	fqdn, entityType, wildcardContext, isValidNode, ok := buildShodanFQDN(target, record.Subdomain)
	if !ok {
		return
	}

	var source *schema.EntityRef
	if isValidNode {
		if record.Type != "TXT" || !strings.HasPrefix(record.Subdomain, "_") {
			source = appendShodanSubdomain(exec, fqdn, entityType, target, wildcardContext, gen)
		}
	}
	value := strings.TrimSpace(record.Value)
	if value == "" {
		return
	}

	lastSeenSource := processShodanDNSRecord(exec, record, value, target, source, gen)
	appendShodanLastSeen(exec, record.LastSeen, lastSeenSource, gen)
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

func appendShodanSubdomain(exec *schema.ModuleExecution, fqdn, entityType, target, wildcardContext string, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	if fqdn == target && wildcardContext == "" {
		return nil
	}

	localID := gen.NextID()
	result := schema.ModuleResult{
		Type:       entityType,
		Category:   constants.CategoryNode,
		Value:      fqdn,
		Tags:       []string{constants.TagPDNS},
		OutOfScope: orgdomain.IsOutOfScope(fqdn, target),
		LocalID:    localID,
	}
	if resolver.ShodanDomainHistory {
		result.Tags = append(result.Tags, constants.TagHistorical)
	}
	if wildcardContext != "" {
		result.Tags = append(result.Tags, constants.TagWildcard)
		result.Context = wildcardContext
	}

	exec.Results = append(exec.Results, result)

	return &schema.EntityRef{Type: entityType, Value: fqdn, LocalID: localID}
}

func processShodanDNSRecord(exec *schema.ModuleExecution, record shodanDomainRecord, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	switch record.Type {
	case "A", "AAAA":
		return appendShodanIPResult(exec, value, source, gen)
	case "CNAME":
		return appendShodanCNAMEResult(exec, value, target, source, gen)
	case "MX":
		return appendShodanMXResult(exec, record, value, target, source, gen)
	case "NS":
		return appendShodanNSResult(exec, value, target, source, gen)
	case "SOA":
		return appendShodanSOAResults(exec, record, value, target, source, gen)
	case "TXT":
		return appendShodanTXTResult(exec, record, value, target, source, gen)
	case "SRV":
		return appendShodanSRVResult(exec, value, target, source, gen)
	case "CAA":
		return appendShodanCAAResult(exec, value, target, source, gen)
	case "URI":
		return appendShodanURIResult(exec, value, target, source, gen)
	case "NAPTR":
		return appendShodanNAPTRResult(exec, value, target, source, gen)
	case "RP":
		return appendShodanRPResult(exec, value, target, source, gen)
	case "HIP":
		return appendShodanHIPResult(exec, value, target, source, gen)
	default:
		return appendShodanGenericDNSResult(exec, record.Type, value, source, gen)
	}
}

func appendShodanIPResult(exec *schema.ModuleExecution, value string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	validated, err := validator.Validate(constants.TypeIP, value)
	if err != nil {
		return nil
	}

	localID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     validated.Type,
		Category: constants.CategoryNode,
		Value:    validated.Value,
		Source:   source,
		LocalID:  localID,
	})

	return &schema.EntityRef{Type: validated.Type, Value: validated.Value, LocalID: localID}
}

func appendShodanCNAMEResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		return nil
	}

	if validated.Value == target {
		return nil
	}

	isOOS := orgdomain.IsOutOfScope(validated.Value, target)
	localID := gen.NextID()

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagCNAME},
		OutOfScope: isOOS,
		Source:     source,
		LocalID:    localID,
	})

	return &schema.EntityRef{Type: validated.Type, Value: validated.Value, LocalID: localID}
}

func appendShodanMXResult(exec *schema.ModuleExecution, record shodanDomainRecord, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	mxValue := value
	if record.Options != nil {
		mxValue = strconv.FormatUint(uint64(record.Options.Priority), 10) + " " + value
	}

	localID := gen.NextID()

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeMX,
		Category: constants.CategoryProperty,
		Value:    mxValue,
		Source:   source,
		LocalID:  localID,
	})

	mxRef := &schema.EntityRef{Type: constants.TypeMX, Value: mxValue, LocalID: localID}

	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		return mxRef
	}

	if validated.Value == target {
		return mxRef
	}

	nodeLocalID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagMX},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     mxRef,
		LocalID:    nodeLocalID,
	})

	return mxRef
}

func appendShodanNSResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	validated, err := validator.Validate(constants.TypeDomain, value)
	if err != nil {
		return nil
	}

	if validated.Value == target {
		return nil
	}

	localID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:       validated.Type,
		Category:   constants.CategoryNode,
		Value:      validated.Value,
		Tags:       []string{constants.TagNS},
		OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
		Source:     source,
		LocalID:    localID,
	})

	return &schema.EntityRef{Type: validated.Type, Value: validated.Value, LocalID: localID}
}

func appendShodanTXTResult(exec *schema.ModuleExecution, record shodanDomainRecord, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
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

	localID := gen.NextID()
	ref := &schema.EntityRef{Type: resultType, Value: value, LocalID: localID}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Context:  contextStr,
		Source:   source,
		LocalID:  localID,
	})

	if resultType == constants.TypeDMARC {
		parsed := dnsutils.ParseDMARC(value)
		for _, key := range []string{"ruf", "rua"} {
			val, ok := parsed[key]
			if !ok {
				continue
			}
			emails := dnsutils.ExtractDMARCEmails(val)
			for _, email := range emails {
				validatedEmail, err := validator.Validate(constants.TypeEmail, email)
				if err != nil {
					continue
				}

				isOOS := orgdomain.IsEmailOutOfScope(validatedEmail.Value, target)

				contextMsg := "DMARC " + strings.ToUpper(key)

				nodeLocalID := gen.NextID()
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:       validatedEmail.Type,
					Category:   constants.CategoryNode,
					Value:      validatedEmail.Value,
					Context:    contextMsg,
					OutOfScope: isOOS,
					Source:     ref,
					LocalID:    nodeLocalID,
				})
			}
		}
	}
	if resultType == constants.TypeSPF {
		for _, ent := range dnsutils.ParseSPF(value) {
			spfResult, ok := buildShodanSPFEntityResult(ref, ent, target, gen)
			if ok {
				exec.Results = append(exec.Results, spfResult)
			}
		}
	}

	return ref
}

func buildShodanSPFEntityResult(source *schema.EntityRef, ent dnsutils.SPFEntity, target string, gen *modutil.LocalIDGenerator) (schema.ModuleResult, bool) {
	switch ent.Kind {
	case dnsutils.SPFEntityIP4, dnsutils.SPFEntityIP6:
		validated, err := validator.Validate(constants.TypeIP, ent.Value)
		if err != nil {
			return schema.ModuleResult{}, false
		}
		localID := gen.NextID()
		return schema.ModuleResult{
			Type:     validated.Type,
			Category: constants.CategoryNode,
			Value:    validated.Value,
			Tags:     []string{constants.TagSPF},
			Context:  "SPF " + ent.Mechanism,
			Source:   source,
			LocalID:  localID,
		}, true
	case dnsutils.SPFEntityDomain:
		validated, err := validator.Validate(constants.TypeDomain, ent.Value)
		if err != nil {
			return schema.ModuleResult{}, false
		}
		if validated.Value == target {
			return schema.ModuleResult{}, false
		}
		localID := gen.NextID()
		return schema.ModuleResult{
			Type:       validated.Type,
			Category:   constants.CategoryNode,
			Value:      validated.Value,
			Tags:       []string{constants.TagSPF},
			Context:    "SPF " + ent.Mechanism,
			OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
			Source:     source,
			LocalID:    localID,
		}, true
	default:
		return schema.ModuleResult{}, false
	}
}

func appendShodanSOAResults(exec *schema.ModuleExecution, record shodanDomainRecord, primaryNS, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	soaRaw := buildShodanSOARaw(primaryNS, record.Options)
	localID := gen.NextID()

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeSOA,
		Category: constants.CategoryProperty,
		Value:    soaRaw,
		Source:   source,
		LocalID:  localID,
	})

	soaRef := &schema.EntityRef{Type: constants.TypeSOA, Value: soaRaw, LocalID: localID}

	if record.Options != nil && record.Options.Serial != 0 {
		serialVal := strconv.FormatUint(record.Options.Serial, 10)
		serialLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeSOA,
			Category: constants.CategoryProperty,
			Value:    serialVal,
			Context:  "Serial",
			Source:   soaRef,
			LocalID:  serialLocalID,
		})
	}

	validatedNS, err := validator.Validate(constants.TypeDomain, primaryNS)
	if err == nil && validatedNS.Value != target {
		nsLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       validatedNS.Type,
			Category:   constants.CategoryNode,
			Value:      validatedNS.Value,
			Tags:       []string{constants.TagNS},
			OutOfScope: orgdomain.IsOutOfScope(validatedNS.Value, target),
			Source:     soaRef,
			LocalID:    nsLocalID,
		})
	}

	if record.Options != nil && record.Options.Hostmaster != "" {
		email := dnsutils.FormatSOAMbox(record.Options.Hostmaster)
		validatedEmail, emailErr := validator.Validate(constants.TypeEmail, email)
		if emailErr == nil {
			emailLocalID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validatedEmail.Type,
				Category:   constants.CategoryNode,
				Value:      validatedEmail.Value,
				OutOfScope: orgdomain.IsEmailOutOfScope(validatedEmail.Value, target),
				Source:     soaRef,
				LocalID:    emailLocalID,
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

func appendShodanGenericDNSResult(exec *schema.ModuleExecution, recordType, value string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	resultType := strings.ToLower(recordType)
	localID := gen.NextID()

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Source:   source,
		LocalID:  localID,
	})

	return &schema.EntityRef{Type: resultType, Value: value, LocalID: localID}
}

func appendShodanLastSeen(exec *schema.ModuleExecution, lastSeen string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	lastSeen = strings.TrimSpace(lastSeen)
	if lastSeen == "" {
		return
	}

	localID := gen.NextID()

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeLastSeen,
		Category: constants.CategoryProperty,
		Value:    lastSeen,
		Source:   source,
		LocalID:  localID,
	})
}

func appendShodanSRVResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	ref := appendShodanGenericDNSResult(exec, "SRV", value, source, gen)
	if host, err := dnsutils.ParseSRVHost(value); err == nil {
		if validated, err := validator.Validate(constants.TypeDomain, host); err == nil && validated.Value != target {
			localID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validated.Type,
				Category:   constants.CategoryNode,
				Value:      validated.Value,
				Tags:       []string{constants.TagSRV},
				OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
				Source:     ref,
				LocalID:    localID,
			})
		}
	}
	return ref
}

func appendShodanCAAResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	normalized, tag, parsedVal, matched := dnsutils.ParseCAA(value)
	ref := appendShodanGenericDNSResult(exec, "CAA", normalized, source, gen)

	if !matched {
		return ref
	}

	switch tag {
	case "issue", "issuewild", "issuemail":
		domain := dnsutils.ExtractCAAAuthority(parsedVal)
		if domain != "" {
			if validated, err := validator.Validate(constants.TypeDomain, domain); err == nil && validated.Value != target {
				localID := gen.NextID()
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:       validated.Type,
					Category:   constants.CategoryNode,
					Value:      validated.Value,
					Tags:       []string{constants.TagCAA},
					OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
					Source:     ref,
					LocalID:    localID,
				})
			}
		}
	case "iodef":
		email := dnsutils.ExtractCAAIodefEmail(parsedVal)
		if email != "" {
			if validated, err := validator.Validate(constants.TypeEmail, email); err == nil {
				localID := gen.NextID()
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:       validated.Type,
					Category:   constants.CategoryNode,
					Value:      validated.Value,
					OutOfScope: orgdomain.IsEmailOutOfScope(validated.Value, target),
					Source:     ref,
					LocalID:    localID,
				})
			}
		}
	}

	return ref
}

func appendShodanURIResult(exec *schema.ModuleExecution, value, _ string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	parsed := dnsutils.ParseURI(value)
	if parsed == nil {
		return appendShodanGenericDNSResult(exec, "URI", value, source, gen)
	}

	ref := appendShodanGenericDNSResult(exec, "URI", parsed.Formatted, source, gen)

	if parsed.Target != "" {
		localID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeURL,
			Category: constants.CategoryProperty,
			Value:    parsed.Target,
			Source:   ref,
			LocalID:  localID,
		})
	}

	return ref
}

func appendShodanNAPTRResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	parsed := dnsutils.ParseNAPTR(value)
	if parsed == nil {
		return appendShodanGenericDNSResult(exec, "NAPTR", value, source, gen)
	}

	ref := appendShodanGenericDNSResult(exec, "NAPTR", parsed.Formatted, source, gen)

	targetSource := ref
	if parsed.Service != "" {
		serviceLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeNAPTR,
			Category: constants.CategoryProperty,
			Value:    parsed.Service,
			Context:  "NAPTR Service",
			Source:   ref,
			LocalID:  serviceLocalID,
		})
		targetSource = &schema.EntityRef{Type: constants.TypeNAPTR, Value: parsed.Service, LocalID: serviceLocalID}
	}

	if parsed.Regexp != "" {
		regexpSource := targetSource
		regexpLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeNAPTR,
			Category: constants.CategoryProperty,
			Value:    parsed.Regexp,
			Context:  "NAPTR Regexp",
			Source:   regexpSource,
			LocalID:  regexpLocalID,
		})
		if parsed.RegexpTarget != "" {
			urlLocalID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeURL,
				Category: constants.CategoryProperty,
				Value:    parsed.RegexpTarget,
				Context:  "NAPTR Regexp Target",
				Source:   &schema.EntityRef{Type: constants.TypeNAPTR, Value: parsed.Regexp, LocalID: regexpLocalID},
				LocalID:  urlLocalID,
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

			localID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validatedType,
				Category:   constants.CategoryNode,
				Value:      validatedValue,
				Tags:       []string{constants.TagNAPTR},
				Context:    contextStr,
				OutOfScope: orgdomain.IsOutOfScope(validatedValue, target),
				Source:     targetSource,
				LocalID:    localID,
			})
		}
	}
	return ref
}

func appendShodanRPResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	ref := appendShodanGenericDNSResult(exec, "RP", value, source, gen)
	parts := strings.Fields(value)
	if len(parts) >= 2 {
		mbox := strings.TrimSuffix(parts[0], ".")
		if idx := strings.Index(mbox, "."); idx > 0 && idx < len(mbox)-1 {
			mbox = mbox[:idx] + "@" + mbox[idx+1:]
		}
		if validated, err := validator.Validate(constants.TypeEmail, mbox); err == nil {
			localID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validated.Type,
				Category:   constants.CategoryNode,
				Value:      validated.Value,
				OutOfScope: orgdomain.IsEmailOutOfScope(validated.Value, target),
				Source:     ref,
				LocalID:    localID,
			})
		}

		txtDomain := strings.TrimSuffix(parts[1], ".")
		if validated, err := validator.Validate(constants.TypeDomain, txtDomain); err == nil && validated.Value != target {
			localID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       validated.Type,
				Category:   constants.CategoryNode,
				Value:      validated.Value,
				Tags:       []string{constants.TagRP},
				OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
				Source:     ref,
				LocalID:    localID,
			})
		}
	}
	return ref
}

func appendShodanHIPResult(exec *schema.ModuleExecution, value, target string, source *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	ref := appendShodanGenericDNSResult(exec, "HIP", value, source, gen)
	parts := strings.Fields(value)
	if len(parts) >= 4 {
		for _, rv := range parts[3:] {
			rvNode := strings.TrimSuffix(rv, ".")
			if validated, err := validator.Validate(constants.TypeDomain, rvNode); err == nil && validated.Value != target {
				localID := gen.NextID()
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:       validated.Type,
					Category:   constants.CategoryNode,
					Value:      validated.Value,
					Tags:       []string{constants.TagHIP},
					OutOfScope: orgdomain.IsOutOfScope(validated.Value, target),
					Source:     ref,
					LocalID:    localID,
				})
			}
		}
	}
	return ref
}
