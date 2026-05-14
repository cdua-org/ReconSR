package shodan

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func extractIPBanners(exec *schema.ModuleExecution, banners []shodanIPBanner, target string) {
	for i := range banners {
		banner := &banners[i]
		serviceSrc := extractBannerServiceAndWeb(exec, banner, target)
		portSrc := extractBannerPort(exec, banner, serviceSrc, target)

		cveSrc := serviceSrc
		if cveSrc == nil {
			cveSrc = portSrc
		}

		extractBannerSSL(exec, banner, portSrc, target)
		extractBannerCPEs(exec, banner, portSrc, target)
		extractBannerVulns(exec, banner, cveSrc, target)
		extractBannerGeo(exec, banner, target)
		extractBannerHash(exec, banner, portSrc, target)
		extractBannerTimestamp(exec, banner, portSrc, target)
		extractBannerHeartbleed(exec, banner, portSrc, target)
	}
}

func extractBannerServiceAndWeb(exec *schema.ModuleExecution, banner *shodanIPBanner, target string) *schema.EntityRef {
	serviceValue := extractBannerServiceValue(banner)
	webServerValue := extractBannerWebServerValue(banner)

	var src *schema.EntityRef
	if serviceValue != "" {
		src = appendBannerSourceResult(exec, constants.TypeService, serviceValue, nil, "Service for "+target)
	}

	if webServerValue != "" {
		if src != nil {
			if serviceValue != webServerValue {
				appendBannerSourceResult(exec, constants.TypeWebServer, webServerValue, src, "Web Server for "+target)
			}
		} else {
			src = appendBannerSourceResult(exec, constants.TypeWebServer, webServerValue, nil, "Web Server for "+target)
		}
	}
	return src
}

func extractBannerPort(exec *schema.ModuleExecution, banner *shodanIPBanner, parentSrc *schema.EntityRef, target string) *schema.EntityRef {
	if banner.Port == 0 {
		return parentSrc
	}

	portValue := strconv.Itoa(banner.Port)
	if transport := formatShodanTransport(banner.Transport); transport != "" {
		portValue += "/" + transport
	}
	if banner.ModuleLabel != "" {
		portValue += " " + banner.ModuleLabel
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypePort,
		Category: constants.CategoryProperty,
		Value:    portValue,
		Context:  "Port for " + target,
		Source:   parentSrc,
	})

	return &schema.EntityRef{Type: constants.TypePort, Value: portValue}
}

func extractBannerServiceValue(banner *shodanIPBanner) string {
	if banner.ServiceValue == nil {
		return ""
	}

	return strings.TrimSpace(*banner.ServiceValue)
}

func extractBannerWebServerValue(banner *shodanIPBanner) string {
	if banner.Details == nil || banner.Details.HTTP == nil {
		return ""
	}

	return strings.TrimSpace(banner.Details.HTTP.Server)
}

func appendBannerSourceResult(exec *schema.ModuleExecution, resultType, value string, src *schema.EntityRef, context string) *schema.EntityRef {
	if value == "" {
		return nil
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Context:  context,
		Source:   src,
	})

	return &schema.EntityRef{Type: resultType, Value: value}
}

func extractBannerCPEs(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, target string) {
	if banner.Artifacts == nil {
		return
	}

	appendBannerStringResults(exec, constants.TypeCPE, banner.Artifacts.CPE, src, "CPE for "+target)
	appendBannerStringResults(exec, constants.TypeCPE23, banner.Artifacts.CPE23, src, "CPE for "+target)
}

func appendBannerStringResults(exec *schema.ModuleExecution, resultType string, values []string, src *schema.EntityRef, context string) {
	for _, value := range values {
		if value == "" {
			continue
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultType,
			Category: constants.CategoryProperty,
			Value:    value,
			Context:  context,
			Source:   src,
		})
	}
}

func extractBannerVulns(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, target string) {
	if banner.Artifacts == nil {
		return
	}

	vulnContext := buildVulnContext(banner, target)

	for cveID, vuln := range banner.Artifacts.Vulns {
		if cveID == "" {
			continue
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVE,
			Category: constants.CategoryNode,
			Value:    cveID,
			Context:  vulnContext,
			Source:   src,
		})

		cveRef := &schema.EntityRef{Type: constants.TypeCVE, Value: cveID}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeVerified,
			Category: constants.CategoryProperty,
			Value:    strconv.FormatBool(vuln.Verified),
			Context:  vulnContext,
			Source:   cveRef,
		})

		if vuln.Summary != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeSummary,
				Category: constants.CategoryProperty,
				Value:    vuln.Summary,
				Context:  vulnContext,
				Source:   cveRef,
			})
		}

		appendVulnScoring(exec, vuln, vulnContext, cveRef)
	}
}

func appendVulnScoring(exec *schema.ModuleExecution, vuln shodanVuln, vulnContext string, cveRef *schema.EntityRef) {
	if vuln.Cvss != 0 {
		cvssValue := strconv.FormatFloat(vuln.Cvss, 'f', -1, 64)
		if vuln.CvssVersion != 0 {
			cvssValue += " (v" + strconv.FormatFloat(vuln.CvssVersion, 'f', 1, 64) + ")"
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVSS,
			Category: constants.CategoryProperty,
			Value:    cvssValue,
			Context:  vulnContext,
			Source:   cveRef,
		})
	}

	if vuln.EPSS != 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeEPSS,
			Category: constants.CategoryProperty,
			Value:    formatPercent(vuln.EPSS),
			Context:  vulnContext,
			Source:   cveRef,
		})
	}

	if vuln.RankingEPSS != 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeRankEPSS,
			Category: constants.CategoryProperty,
			Value:    formatPercent(vuln.RankingEPSS),
			Context:  vulnContext,
			Source:   cveRef,
		})
	}
}

func formatPercent(v float64) string {
	return strconv.FormatFloat(v*100, 'f', 2, 64) + "%"
}

func buildVulnContext(banner *shodanIPBanner, target string) string {
	var b strings.Builder
	b.WriteString(target)

	if banner.Port != 0 {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(banner.Port))
		if transport := formatShodanTransport(banner.Transport); transport != "" {
			b.WriteByte('/')
			b.WriteString(transport)
		}
	}

	if svc := extractBannerServiceValue(banner); svc != "" {
		b.WriteString(" (")
		b.WriteString(svc)
		b.WriteByte(')')
	}

	return b.String()
}

func extractBannerGeo(exec *schema.ModuleExecution, banner *shodanIPBanner, target string) {
	if banner.Details == nil || banner.Details.Location == nil {
		return
	}

	location := banner.Details.Location
	geoParts := make([]string, 0, 3)
	if location.City != "" {
		geoParts = append(geoParts, "City: "+location.City)
	}
	if country := formatShodanCountry(location); country != "" {
		geoParts = append(geoParts, "Country: "+country)
	}
	if location.Latitude != 0 || location.Longitude != 0 {
		geoParts = append(geoParts, fmt.Sprintf("Lat/Lon: %f, %f", location.Latitude, location.Longitude))
	}
	if len(geoParts) == 0 {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeGeo,
		Category: constants.CategoryProperty,
		Value:    strings.Join(geoParts, " | "),
		Context:  "Location for " + target,
	})
}

func formatShodanCountry(location *shodanBannerLocation) string {
	switch {
	case location.CountryName != "" && location.CountryCode != "":
		return location.CountryName + " (" + location.CountryCode + ")"
	case location.CountryName != "":
		return location.CountryName
	default:
		return location.CountryCode
	}
}

func extractBannerHash(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, target string) {
	if banner.Hash == 0 {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeHash,
		Category: constants.CategoryProperty,
		Value:    strconv.FormatInt(banner.Hash, 10),
		Context:  "Hash for " + target,
		Source:   src,
	})
}

func extractBannerTimestamp(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, target string) {
	if banner.Timestamp == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeBannerTimestamp,
		Category: constants.CategoryProperty,
		Value:    banner.Timestamp,
		Context:  "Banner Timestamp for " + target,
		Source:   src,
	})
}

func extractBannerHeartbleed(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, target string) {
	if banner.Heartbleed == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeHeartbleed,
		Category: constants.CategoryProperty,
		Value:    banner.Heartbleed,
		Context:  "Heartbleed for " + target,
		Source:   src,
	})
}
