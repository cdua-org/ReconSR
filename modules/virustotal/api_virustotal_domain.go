package virustotal

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dateutil"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

const vtTimeFormat = "2006-01-02 15:04:05"

func (m *module) extractDomainMetadata(attr map[string]any, targetType, target string, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	tags := extractVTTags(attr)
	for _, tag := range tags {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    tag,
			LocalID:  gen.NextID(),
		})
	}

	if records, ok := attr["last_dns_records"].([]any); ok {
		for _, r := range records {
			if rec, ok := r.(map[string]any); ok {
				m.parseDNSRecord(rec, target, nil, exec, gen)
			}
		}
	}

	m.extractThreatScore(attr, targetType, target, nil, exec, gen)
	appendDomainCategories(exec, attr, gen)
	appendDomainReputation(exec, attr, gen)
	appendDomainPopularityRanks(exec, attr, gen)
	appendDomainJARM(exec, attr, target, gen)
	appendDomainCrowdsourcedContext(exec, attr, gen)
	appendDomainLastUpdate(exec, attr, target, gen)
	appendDomainCertificateSummary(exec, attr, targetType, target, gen)

	if _, ok := attr["whois"]; ok {
		dbg.Printf("%s ignored_field=whois target=%q", constants.FuncGetVTApiDomain, target)
	}
	if _, ok := attr["rdap"]; ok {
		dbg.Printf("%s ignored_field=rdap target=%q", constants.FuncGetVTApiDomain, target)
	}
	for key := range attr {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "registrar") || strings.Contains(keyLower, "registrant") {
			dbg.Printf("%s ignored_field=%q target=%q", constants.FuncGetVTApiDomain, key, target)
		}
	}
}

func appendDomainCategories(exec *schema.ModuleExecution, attr map[string]any, gen *modutil.LocalIDGenerator) {
	categories, ok := attr["categories"].(map[string]any)
	if !ok || len(categories) == 0 {
		return
	}

	providers := make([]string, 0, len(categories))
	for provider := range categories {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	for _, provider := range providers {
		category, ok := categories[provider].(string)
		if !ok {
			continue
		}
		appendVTProperty(exec, constants.TypeInfo, category, "VirusTotal Category by "+provider, nil, gen)
	}
}

func appendDomainReputation(exec *schema.ModuleExecution, attr map[string]any, gen *modutil.LocalIDGenerator) {
	reputationFloat, ok := attr["reputation"].(float64)
	if !ok {
		return
	}

	reputation := int(reputationFloat)
	if reputation >= 0 {
		return
	}

	value := fmt.Sprintf("%d (Malicious/Suspicious)", reputation)
	appendVTProperty(exec, constants.TypeVTReputation, value, "VirusTotal Community Reputation", nil, gen)
}

func appendDomainPopularityRanks(exec *schema.ModuleExecution, attr map[string]any, gen *modutil.LocalIDGenerator) {
	popularityRanks, ok := attr["popularity_ranks"].(map[string]any)
	if !ok || len(popularityRanks) == 0 {
		return
	}

	providers := make([]string, 0, len(popularityRanks))
	for provider := range popularityRanks {
		providers = append(providers, provider)
	}
	sort.Strings(providers)

	for _, provider := range providers {
		rankEntry, ok := popularityRanks[provider].(map[string]any)
		if !ok {
			continue
		}
		rank, ok := formatVTInt(rankEntry["rank"])
		if !ok {
			continue
		}
		appendVTProperty(exec, constants.TypeInfo, rank, "VirusTotal Popularity Rank by "+provider, nil, gen)
	}
}

func appendDomainJARM(exec *schema.ModuleExecution, attr map[string]any, target string, gen *modutil.LocalIDGenerator) {
	jarm, ok := attr["jarm"].(string)
	if !ok {
		return
	}

	appendVTProperty(exec, constants.TypeJARM, jarm, "JARM for "+target, nil, gen)
}

func appendDomainCrowdsourcedContext(exec *schema.ModuleExecution, attr map[string]any, gen *modutil.LocalIDGenerator) {
	entries, ok := attr["crowdsourced_context"].([]any)
	if !ok || len(entries) == 0 {
		return
	}

	for _, entry := range entries {
		item, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		title := ""
		if rawTitle, titleOK := item["title"].(string); titleOK {
			title = rawTitle
		}

		details := ""
		if rawDetails, detailsOK := item["details"].(string); detailsOK {
			details = rawDetails
		}

		value := normalizeVTText(details)
		resultContext := strings.TrimSpace(title)
		if resultContext == "" {
			resultContext = "VirusTotal Crowdsourced Context"
		}
		appendVTProperty(exec, constants.TypeSummary, value, resultContext, nil, gen)
	}
}

func appendDomainLastUpdate(exec *schema.ModuleExecution, attr map[string]any, _ string, gen *modutil.LocalIDGenerator) {
	lastUpdateRaw, ok := attr["last_modification_date"].(float64)
	if !ok {
		return
	}

	formattedDate := time.Unix(int64(lastUpdateRaw), 0).UTC().Format(time.RFC3339)
	if day, ok := dateutil.NormalizeDay(formattedDate); ok {
		formattedDate = day
	}
	appendVTProperty(exec, constants.TypeDate, "Last Update: "+formattedDate, "", nil, gen)
}

func appendDomainCertificateSummary(exec *schema.ModuleExecution, attr map[string]any, targetType, target string, gen *modutil.LocalIDGenerator) {
	certificate, ok := attr["last_https_certificate"].(map[string]any)
	if !ok {
		return
	}

	sources := appendVTCertificateSANs(exec, certificate, targetType, target, gen)
	issuer := formatVTCertificateIssuer(certificate)
	notAfter := extractVTCertificateNotAfter(certificate)

	if len(sources) == 0 {
		appendVTProperty(exec, constants.TypeCertIssuer, issuer, "Cert Issuer for "+target, nil, gen)
		appendVTProperty(exec, constants.TypeCertNotAfter, notAfter, "Cert Expiration for "+target, nil, gen)
	} else {
		for _, source := range sources {
			appendVTProperty(exec, constants.TypeCertIssuer, issuer, "Cert Issuer for "+target, source, gen)
			appendVTProperty(exec, constants.TypeCertNotAfter, notAfter, "Cert Expiration for "+target, source, gen)
		}
	}

	for k, v := range certificate {
		strVal, ok := v.(string)
		if !ok || !strings.HasPrefix(k, "thumbprint") {
			continue
		}

		algo := "sha1"
		if suffix, found := strings.CutPrefix(k, "thumbprint_"); found {
			algo = suffix
		}

		appendVTProperty(exec, constants.TypeCertFingerprint, algo+":"+strVal, "Cert Fingerprint for "+target, nil, gen)
	}
}

func appendVTCertificateSANs(exec *schema.ModuleExecution, certificate map[string]any, targetType, target string, gen *modutil.LocalIDGenerator) []*schema.EntityRef {
	extensions, ok := certificate["extensions"].(map[string]any)
	if !ok {
		return nil
	}

	rawSANs, ok := extensions["subject_alternative_name"].([]any)
	if !ok || len(rawSANs) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(rawSANs))
	sources := make([]*schema.EntityRef, 0, len(rawSANs))
	for _, rawSAN := range rawSANs {
		san, ok := rawSAN.(string)
		if !ok {
			continue
		}
		resultType, resultValue, wildcardContext, valid := classifyVTCertificateSAN(san)
		if !valid {
			continue
		}

		cacheKey := resultType + ":" + resultValue + ":" + wildcardContext
		if _, exists := seen[cacheKey]; exists {
			continue
		}
		seen[cacheKey] = struct{}{}

		var src *schema.EntityRef
		if resultValue != target || wildcardContext != "" {
			result := schema.ModuleResult{
				Type:       resultType,
				Category:   constants.CategoryNode,
				Value:      resultValue,
				Tags:       []string{constants.TagSan},
				OutOfScope: orgdomain.IsOutOfScope(resultValue, target),
				LocalID:    gen.NextID(),
			}
			if resultValue != target {
				result.Source = &schema.EntityRef{
					Type:  targetType,
					Value: target,
				}
			}
			if wildcardContext != "" {
				result.Tags = append(result.Tags, constants.TagWildcard)
				result.Context = wildcardContext
			}
			exec.Results = append(exec.Results, result)
			src = &schema.EntityRef{Type: resultType, Value: resultValue, LocalID: result.LocalID}
		}

		sources = append(sources, src)
	}

	return sources
}

func classifyVTCertificateSAN(value string) (resultType, resultValue, wildcardContext string, ok bool) {
	trimmedValue := strings.TrimSpace(value)
	candidate := trimmedValue
	if trimmedWildcard, found := strings.CutPrefix(trimmedValue, "*."); found {
		candidate = trimmedWildcard
	}
	if candidate == "" {
		return "", "", "", false
	}

	validated, err := validator.Validate(constants.TypeDomain, candidate)
	if err != nil {
		return "", "", "", false
	}

	if candidate != trimmedValue {
		wildcardContext = "*." + validated.Value
	}

	return validated.Type, validated.Value, wildcardContext, true
}

func formatVTCertificateIssuer(certificate map[string]any) string {
	issuer, ok := certificate["issuer"].(map[string]any)
	if !ok {
		return ""
	}

	parts := make([]string, 0, 3)
	if organization, ok := issuer["O"].(string); ok && organization != "" {
		parts = append(parts, "O: "+organization)
	}
	if commonName, ok := issuer["CN"].(string); ok && commonName != "" {
		parts = append(parts, "CN: "+commonName)
	}
	if country, ok := issuer["C"].(string); ok && country != "" {
		parts = append(parts, "C: "+country)
	}

	return strings.Join(parts, " | ")
}

func extractVTCertificateNotAfter(certificate map[string]any) string {
	validity, ok := certificate["validity"].(map[string]any)
	if !ok {
		return ""
	}

	value, ok := validity["not_after"].(string)
	if !ok {
		return ""
	}

	return strings.TrimSpace(value)
}

func parseVTCertificateExpiration(attr map[string]any) (string, bool) {
	cert, ok := attr["last_https_certificate"].(map[string]any)
	if !ok {
		return "", false
	}

	notAfter := extractVTCertificateNotAfter(cert)
	if notAfter == "" {
		return "", false
	}

	isExpired := false
	notAfterStr := notAfter

	if t, err := time.Parse(vtTimeFormat, notAfter); err == nil {
		if !t.IsZero() && !t.After(time.Now()) {
			isExpired = true
		}
		notAfterStr = t.UTC().Format(time.RFC3339)
	} else if t, err := time.Parse(time.RFC3339, notAfter); err == nil {
		if !t.IsZero() && !t.After(time.Now()) {
			isExpired = true
		}
		notAfterStr = t.UTC().Format(time.RFC3339)
	}

	return notAfterStr, isExpired
}

func (m *module) extractSubdomain(item map[string]any, parentType, parent string, disableCertExpired bool, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) string {
	sub, ok := item["id"].(string)
	if !ok {
		return ""
	}

	validatedSubdomain, err := validator.Validate(constants.TypeDomain, sub)
	if err != nil {
		dbg.Printf("%s skip_invalid_subdomain parent=%q value=%q err=%v", constants.FuncGetVTApiDomain, parent, sub, err)
		return ""
	}

	attr, ok := item["attributes"].(map[string]any)
	if !ok {
		attr = map[string]any{}
	}

	notAfterStr, isExpired := parseVTCertificateExpiration(attr)

	if isExpired && !disableCertExpired {
		return fmt.Sprintf("%s (%s)", validatedSubdomain.Value, notAfterStr)
	}

	isOOS := orgdomain.IsOutOfScope(validatedSubdomain.Value, parent)
	subEntity := schema.ModuleResult{
		Type:       validatedSubdomain.Type,
		Category:   constants.CategoryNode,
		Value:      validatedSubdomain.Value,
		Context:    "VirusTotal Subdomain Enumeration",
		Tags:       []string{constants.TagPDNS},
		OutOfScope: isOOS,
		Source: &schema.EntityRef{
			Type:  parentType,
			Value: parent,
		},
		LocalID: gen.NextID(),
	}
	exec.Results = append(exec.Results, subEntity)

	subRef := &schema.EntityRef{Type: validatedSubdomain.Type, Value: validatedSubdomain.Value, LocalID: subEntity.LocalID}

	if notAfterStr != "" {
		tags := extractVTTags(attr)
		for _, tag := range tags {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeTag,
				Category: constants.CategoryProperty,
				Value:    tag,
				LocalID:  gen.NextID(),
			})
		}
		appendVTProperty(exec, constants.TypeCertNotAfter, notAfterStr, "Cert Expiration for "+validatedSubdomain.Value, subRef, gen)
		if isExpired {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeStatus,
				Category: constants.CategoryProperty,
				Value:    constants.StatusExpired,
				Source: &schema.EntityRef{
					Type:  constants.TypeCertNotAfter,
					Value: notAfterStr,
				},
				LocalID: gen.NextID(),
			})
		}
	}

	if lastUpdateRaw, ok := attr["last_modification_date"].(float64); ok {
		formattedDate := time.Unix(int64(lastUpdateRaw), 0).UTC().Format(time.RFC3339)
		if day, ok := dateutil.NormalizeDay(formattedDate); ok {
			formattedDate = day
		}
		appendVTProperty(exec, constants.TypeDate, "Last Update: "+formattedDate, "", subRef, gen)
	}

	m.appendSubdomainDeepResults(attr, parentType, parent, subRef, exec, gen)
	m.logIgnoredSubdomainFields(attr, validatedSubdomain.Value)

	return ""
}

func (m *module) appendSubdomainDeepResults(attr map[string]any, _, scopeTarget string, subRef *schema.EntityRef, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	if records, ok := attr["last_dns_records"].([]any); ok {
		for _, r := range records {
			if rec, ok := r.(map[string]any); ok {
				m.parseDNSRecord(rec, scopeTarget, subRef, exec, gen)
			}
		}
	}

	m.extractThreatScore(attr, subRef.Type, subRef.Value, subRef, exec, gen)
}

func (m *module) logIgnoredSubdomainFields(attr map[string]any, subdomain string) {
	for _, field := range []string{"whois", "rdap"} {
		if _, ok := attr[field]; ok {
			dbg.Printf("%s ignored_field=%q subdomain=%q", constants.FuncGetVTApiDomain, field, subdomain)
		}
	}

	for key := range attr {
		keyLower := strings.ToLower(key)
		if strings.Contains(keyLower, "registrar") || strings.Contains(keyLower, "registrant") {
			dbg.Printf("%s ignored_field=%q subdomain=%q", constants.FuncGetVTApiDomain, key, subdomain)
		}
	}
}
