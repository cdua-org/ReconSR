package shodan

import (
	"regexp"
	"strings"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/schema"
)

const (
	subjectAltNameExtension = "subjectAltName"
	shodanCertTimeLayout    = "20060102150405Z"
)

var (
	shodanEscapedSequenceRegex = regexp.MustCompile(`\\x[0-9A-Fa-f]{2}|\\[tnr]`)
	shodanDomainPatternRegex   = regexp.MustCompile(`(?i)(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,63}`)
)

func extractBannerSSL(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, source *schema.EntityRef) {
	if banner.Details == nil || banner.Details.SSL == nil {
		return
	}

	for _, extension := range banner.Details.SSL.Extensions {
		if extension.Name != subjectAltNameExtension {
			continue
		}

		sources := parseSubjectAltName(exec, extension.Data, tags)
		appendSubjectAltNameMetadata(exec, banner.Details.SSL, tags, sources)
	}

	appendBannerSSLProperties(exec, banner.Details.SSL, tags, source)
}

func parseSubjectAltName(exec *schema.ModuleExecution, value string, tags []string) []schema.EntityRef {
	normalized := shodanEscapedSequenceRegex.ReplaceAllString(value, " ")
	matches := shodanDomainPatternRegex.FindAllString(normalized, -1)
	seen := make(map[string]struct{}, len(matches))
	sources := make([]schema.EntityRef, 0, len(matches))

	for _, match := range matches {
		resultType, resultValue, ok := classifySubjectAltName(match)
		if !ok {
			continue
		}
		cacheKey := resultType + ":" + resultValue
		if _, exists := seen[cacheKey]; exists {
			continue
		}
		seen[cacheKey] = struct{}{}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultType,
			Category: resultCategoryNode,
			Value:    resultValue,
			Tags:     tags,
		})
		sources = append(sources, schema.EntityRef{Type: resultType, Value: resultValue})
	}

	return sources
}

func classifySubjectAltName(match string) (resultType, resultValue string, ok bool) {
	isWildcard := strings.HasPrefix(match, "*.")
	candidate := strings.TrimPrefix(match, "*.")
	if candidate == "" {
		return "", "", false
	}

	validated, err := validator.Validate(entityTypeDomain, candidate)
	if err != nil {
		return "", "", false
	}

	if !isWildcard {
		return resultTypeSANDomain, validated.Value, true
	}

	return resultTypeWildcardSANDomain, "*." + validated.Value, true
}

func appendSubjectAltNameMetadata(exec *schema.ModuleExecution, ssl *shodanSSLBanner, tags []string, sources []schema.EntityRef) {
	if len(sources) == 0 {
		return
	}

	issuerValue := ssl.CertIssuerValue
	notAfterValue := ssl.CertNotAfterValue
	tlsVersionsValue := ssl.TLSVersionsValue

	for i := range sources {
		source := &sources[i]
		appendSubjectAltNameProperty(exec, resultTypeCertIssuer, issuerValue, tags, source)
		appendSubjectAltNameProperty(exec, resultTypeCertNotAfter, notAfterValue, tags, source)
		appendSubjectAltNameProperty(exec, resultTypeTLSVersions, tlsVersionsValue, tags, source)
	}
}

func appendSubjectAltNameProperty(exec *schema.ModuleExecution, resultType, value string, tags []string, source *schema.EntityRef) {
	if value == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: resultCategoryProperty,
		Value:    value,
		Tags:     tags,
		Source:   source,
	})
}

func appendBannerSSLProperties(exec *schema.ModuleExecution, ssl *shodanSSLBanner, tags []string, source *schema.EntityRef) {
	if ssl == nil {
		return
	}

	for _, fingerprint := range ssl.CertFingerprintValues {
		appendBannerSSLProperty(exec, resultTypeCertFingerprint, fingerprint, tags, source)
	}
	appendBannerSSLProperty(exec, resultTypeJARM, ssl.JARMValue, tags, source)
}

func appendBannerSSLProperty(exec *schema.ModuleExecution, resultType, value string, tags []string, source *schema.EntityRef) {
	if value == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: resultCategoryProperty,
		Value:    value,
		Tags:     tags,
		Source:   source,
	})
}

func formatShodanCertIssuer(issuer *shodanCertIssuer) string {
	if issuer == nil {
		return ""
	}

	parts := make([]string, 0, 3)
	if issuer.Org != "" {
		parts = append(parts, "O: "+issuer.Org)
	}
	if issuer.CommonName != "" {
		parts = append(parts, "CN: "+issuer.CommonName)
	}
	if issuer.Country != "" {
		parts = append(parts, "C: "+issuer.Country)
	}

	return strings.Join(parts, " | ")
}

func formatShodanCertTime(value string) string {
	if value == "" {
		return ""
	}

	parsed, err := time.Parse(shodanCertTimeLayout, value)
	if err != nil {
		return value
	}

	return parsed.UTC().Format(time.RFC3339)
}

func formatShodanTLSVersions(versions []string) string {
	if len(versions) == 0 {
		return ""
	}

	available := make([]string, 0, len(versions))
	for _, version := range versions {
		if version == "" || strings.HasPrefix(version, "-") {
			continue
		}
		available = append(available, version)
	}
	if len(available) == 0 {
		return ""
	}

	return strings.Join(available, ", ")
}
