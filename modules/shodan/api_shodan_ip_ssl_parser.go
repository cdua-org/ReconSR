package shodan

import (
	"regexp"
	"strings"
	"time"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
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

func extractBannerSSL(exec *schema.ModuleExecution, banner *shodanIPBanner, source *schema.EntityRef, target string) {
	if banner.Details == nil || banner.Details.SSL == nil {
		return
	}

	for _, extension := range banner.Details.SSL.Extensions {
		if extension.Name != subjectAltNameExtension {
			continue
		}

		sources := parseSubjectAltName(exec, extension.Data)
		appendSubjectAltNameMetadata(exec, banner.Details.SSL, sources, target)
	}

	appendBannerSSLProperties(exec, banner.Details.SSL, source, target)
}

func parseSubjectAltName(exec *schema.ModuleExecution, value string) []schema.EntityRef {
	normalized := shodanEscapedSequenceRegex.ReplaceAllString(value, " ")
	matches := shodanDomainPatternRegex.FindAllString(normalized, -1)
	seen := make(map[string]struct{}, len(matches))
	sources := make([]schema.EntityRef, 0, len(matches))

	for _, match := range matches {
		resultType, resultValue, wildcardContext, ok := classifySubjectAltName(match)
		if !ok {
			continue
		}
		cacheKey := resultType + ":" + resultValue + ":" + wildcardContext
		if _, exists := seen[cacheKey]; exists {
			continue
		}
		seen[cacheKey] = struct{}{}

		result := schema.ModuleResult{
			Type:     resultType,
			Category: constants.CategoryNode,
			Value:    resultValue,
			Tags:     []string{constants.TagSan},
		}
		if wildcardContext != "" {
			result.Tags = append(result.Tags, constants.TagWildcard)
			result.Context = wildcardContext
		}

		exec.Results = append(exec.Results, result)
		sources = append(sources, schema.EntityRef{Type: resultType, Value: resultValue})
	}

	return sources
}

func classifySubjectAltName(match string) (resultType, resultValue, wildcardContext string, ok bool) {
	candidate := match
	isWildcard := false
	if trimmedWildcard, found := strings.CutPrefix(match, "*."); found {
		candidate = trimmedWildcard
		isWildcard = true
	}
	if candidate == "" {
		return "", "", "", false
	}

	validated, err := validator.Validate(constants.TypeDomain, candidate)
	if err != nil {
		return "", "", "", false
	}

	if isWildcard {
		wildcardContext = "*." + validated.Value
	}

	return validated.Type, validated.Value, wildcardContext, true
}

func appendSubjectAltNameMetadata(exec *schema.ModuleExecution, ssl *shodanSSLBanner, sources []schema.EntityRef, target string) {
	if len(sources) == 0 {
		return
	}

	issuerValue := ssl.CertIssuerValue
	notAfterValue := ssl.CertNotAfterValue
	tlsVersionsValue := ssl.TLSVersionsValue

	for i := range sources {
		source := &sources[i]
		appendSubjectAltNameProperty(exec, constants.TypeCertIssuer, issuerValue, source, "Cert Issuer for "+target)
		appendSubjectAltNameProperty(exec, constants.TypeCertNotAfter, notAfterValue, source, "Cert Expiration for "+target)
		appendSubjectAltNameProperty(exec, constants.TypeTLSVersions, tlsVersionsValue, source, "TLS Versions for "+target)
	}
}

func appendSubjectAltNameProperty(exec *schema.ModuleExecution, resultType, value string, source *schema.EntityRef, context string) {
	if value == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Context:  context,
		Source:   source,
	})
}

func appendBannerSSLProperties(exec *schema.ModuleExecution, ssl *shodanSSLBanner, source *schema.EntityRef, target string) {
	if ssl == nil {
		return
	}

	for _, fingerprint := range ssl.CertFingerprintValues {
		appendBannerSSLProperty(exec, constants.TypeCertFingerprint, fingerprint, source, "Cert Fingerprint for "+target)
	}
	appendBannerSSLProperty(exec, constants.TypeJARM, ssl.JARMValue, source, "JARM for "+target)
}

func appendBannerSSLProperty(exec *schema.ModuleExecution, resultType, value string, source *schema.EntityRef, context string) {
	if value == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Context:  context,
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
