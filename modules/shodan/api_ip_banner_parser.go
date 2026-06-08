package shodan

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func extractIPBanners(exec *schema.ModuleExecution, banners []shodanIPBanner, gen *modutil.LocalIDGenerator) {
	for i := range banners {
		banner := &banners[i]
		portSrc := extractBannerPort(exec, banner, nil, gen)
		serviceSrc := extractBannerServiceAndWeb(exec, banner, portSrc, gen)

		softwareSrc := serviceSrc
		if softwareSrc == nil {
			softwareSrc = portSrc
		}

		extractBannerSSL(exec, banner, portSrc, gen)
		extractBannerCPEs(exec, banner, softwareSrc, gen)
		extractBannerVulns(exec, banner, softwareSrc, gen)
		extractBannerGeo(exec, banner, gen)
		extractBannerHash(exec, banner, portSrc, gen)
		extractBannerTimestamp(exec, banner, portSrc, gen)
		extractBannerHeartbleed(exec, banner, softwareSrc, gen)
	}
}

func extractBannerServiceAndWeb(exec *schema.ModuleExecution, banner *shodanIPBanner, parentSrc *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	serviceValue := extractBannerServiceValue(banner)
	webServerValue := extractBannerWebServerValue(banner)

	var src *schema.EntityRef
	if serviceValue != "" {
		src = appendBannerSourceResult(exec, constants.TypeService, serviceValue, parentSrc, gen)
	}

	if webServerValue != "" {
		if src != nil {
			if serviceValue != webServerValue {
				appendBannerSourceResult(exec, constants.TypeWebServer, webServerValue, src, gen)
			}
		} else {
			src = appendBannerSourceResult(exec, constants.TypeWebServer, webServerValue, parentSrc, gen)
		}
	}
	return src
}

func extractBannerPort(exec *schema.ModuleExecution, banner *shodanIPBanner, parentSrc *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
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

	localID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypePort,
		Category: constants.CategoryProperty,
		Value:    portValue,
		Source:   parentSrc,
		LocalID:  localID,
	})

	return &schema.EntityRef{Type: constants.TypePort, Value: portValue, LocalID: localID}
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

func appendBannerSourceResult(exec *schema.ModuleExecution, resultType, value string, src *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	if value == "" {
		return nil
	}

	localID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: constants.CategoryProperty,
		Value:    value,
		Source:   src,
		LocalID:  localID,
	})

	return &schema.EntityRef{Type: resultType, Value: value, LocalID: localID}
}

func extractBannerCPEs(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if banner.Artifacts == nil {
		return
	}

	appendBannerStringResults(exec, constants.TypeCPE, banner.Artifacts.CPE, src, gen)
	appendBannerStringResults(exec, constants.TypeCPE23, banner.Artifacts.CPE23, src, gen)
}

func appendBannerStringResults(exec *schema.ModuleExecution, resultType string, values []string, src *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	for _, value := range values {
		if value == "" {
			continue
		}

		localID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultType,
			Category: constants.CategoryProperty,
			Value:    value,
			Source:   src,
			LocalID:  localID,
		})
	}
}

func extractBannerVulns(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if banner.Artifacts == nil {
		return
	}

	for cveID, vuln := range banner.Artifacts.Vulns {
		if cveID == "" {
			continue
		}

		cveLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVE,
			Category: constants.CategoryProperty,
			Value:    cveID,
			Source:   src,
			LocalID:  cveLocalID,
		})

		cveRef := &schema.EntityRef{Type: constants.TypeCVE, Value: cveID, LocalID: cveLocalID}

		verifiedLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeVerified,
			Category: constants.CategoryProperty,
			Value:    strconv.FormatBool(vuln.Verified),
			Source:   cveRef,
			LocalID:  verifiedLocalID,
		})

		if vuln.Summary != "" {
			summaryLocalID := gen.NextID()
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeSummary,
				Category: constants.CategoryProperty,
				Value:    vuln.Summary,
				Source:   cveRef,
				LocalID:  summaryLocalID,
			})
		}

		appendVulnScoring(exec, vuln, cveRef, gen)
	}
}

func appendVulnScoring(exec *schema.ModuleExecution, vuln shodanVuln, cveRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if vuln.Cvss != 0 {
		cvssValue := strconv.FormatFloat(vuln.Cvss, 'f', -1, 64)
		if vuln.CvssVersion != 0 {
			cvssValue += " (v" + strconv.FormatFloat(vuln.CvssVersion, 'f', 1, 64) + ")"
		}
		cvssLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVSS,
			Category: constants.CategoryProperty,
			Value:    cvssValue,
			Source:   cveRef,
			LocalID:  cvssLocalID,
		})
	}

	if vuln.EPSS != 0 {
		epssVal := formatPercent(vuln.EPSS)
		epssLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeEPSS,
			Category: constants.CategoryProperty,
			Value:    epssVal,
			Source:   cveRef,
			LocalID:  epssLocalID,
		})
	}

	if vuln.RankingEPSS != 0 {
		rankVal := formatPercent(vuln.RankingEPSS)
		rankLocalID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeRankEPSS,
			Category: constants.CategoryProperty,
			Value:    rankVal,
			Source:   cveRef,
			LocalID:  rankLocalID,
		})
	}
}

func formatPercent(v float64) string {
	return strconv.FormatFloat(v*100, 'f', 2, 64) + "%"
}

func extractBannerGeo(exec *schema.ModuleExecution, banner *shodanIPBanner, gen *modutil.LocalIDGenerator) {
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
		LocalID:  gen.NextID(),
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

func extractBannerHash(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if banner.Hash == 0 {
		return
	}

	hashStr := strconv.FormatInt(banner.Hash, 10)
	localID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeHash,
		Category: constants.CategoryProperty,
		Value:    hashStr,
		Source:   src,
		LocalID:  localID,
	})
}

func extractBannerTimestamp(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if banner.Timestamp == "" {
		return
	}

	localID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeBannerTimestamp,
		Category: constants.CategoryProperty,
		Value:    banner.Timestamp,
		Source:   src,
		LocalID:  localID,
	})
}

func extractBannerHeartbleed(exec *schema.ModuleExecution, banner *shodanIPBanner, src *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if banner.Heartbleed == "" {
		return
	}

	localID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeHeartbleed,
		Category: constants.CategoryProperty,
		Value:    banner.Heartbleed,
		Source:   src,
		LocalID:  localID,
	})
}
