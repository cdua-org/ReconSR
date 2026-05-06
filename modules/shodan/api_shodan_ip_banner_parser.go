package shodan

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/schema"
)

func extractIPBanners(exec *schema.ModuleExecution, banners []shodanIPBanner, tags []string, target string) {
	for i := range banners {
		banner := &banners[i]
		serviceSrc := extractBannerServiceAndWeb(exec, banner, tags, target)
		portSrc := extractBannerPort(exec, banner, tags, serviceSrc, target)

		cveSrc := serviceSrc
		if cveSrc == nil {
			cveSrc = portSrc
		}

		extractBannerSSL(exec, banner, tags, portSrc, target)
		extractBannerCPEs(exec, banner, tags, portSrc, target)
		extractBannerVulns(exec, banner, tags, cveSrc, target)
		extractBannerGeo(exec, banner, tags, target)
		extractBannerHash(exec, banner, tags, portSrc, target)
		extractBannerTimestamp(exec, banner, tags, portSrc, target)
		extractBannerHeartbleed(exec, banner, tags, portSrc, target)
	}
}

func extractBannerServiceAndWeb(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, target string) *schema.EntityRef {
	serviceValue := extractBannerServiceValue(banner)
	webServerValue := extractBannerWebServerValue(banner)

	var src *schema.EntityRef
	if serviceValue != "" {
		src = appendBannerSourceResult(exec, resultTypeService, serviceValue, tags, nil, "Service for "+target)
	}

	if webServerValue != "" {
		if src != nil {
			if serviceValue != webServerValue {
				appendBannerSourceResult(exec, resultTypeWebServer, webServerValue, tags, src, "Web Server for "+target)
			}
		} else {
			src = appendBannerSourceResult(exec, resultTypeWebServer, webServerValue, tags, nil, "Web Server for "+target)
		}
	}
	return src
}

func extractBannerPort(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, parentSrc *schema.EntityRef, target string) *schema.EntityRef {
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
		Type:     resultTypePort,
		Category: resultCategoryProperty,
		Value:    portValue,
		Context:  "Port for " + target,
		Tags:     tags,
		Source:   parentSrc,
	})

	return &schema.EntityRef{Type: resultTypePort, Value: portValue}
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

func appendBannerSourceResult(exec *schema.ModuleExecution, resultType, value string, tags []string, src *schema.EntityRef, context string) *schema.EntityRef {
	if value == "" {
		return nil
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: resultCategoryProperty,
		Value:    value,
		Context:  context,
		Tags:     tags,
		Source:   src,
	})

	return &schema.EntityRef{Type: resultType, Value: value}
}

func extractBannerCPEs(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, src *schema.EntityRef, target string) {
	if banner.Artifacts == nil {
		return
	}

	appendBannerStringResults(exec, resultTypeCPE, banner.Artifacts.CPE, tags, src, "CPE for "+target)
	appendBannerStringResults(exec, "cpe23", banner.Artifacts.CPE23, tags, src, "CPE for "+target)
}

func appendBannerStringResults(exec *schema.ModuleExecution, resultType string, values, tags []string, src *schema.EntityRef, context string) {
	for _, value := range values {
		if value == "" {
			continue
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultType,
			Category: resultCategoryProperty,
			Value:    value,
			Context:  context,
			Tags:     tags,
			Source:   src,
		})
	}
}

func extractBannerVulns(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, src *schema.EntityRef, target string) {
	if banner.Artifacts == nil {
		return
	}

	for cveID, vuln := range banner.Artifacts.Vulns {
		if vuln.Summary == "" {
			continue
		}

		value := fmt.Sprintf("%s | Verified: %t | Summary: %s", cveID, vuln.Verified, vuln.Summary)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultTypeCVE,
			Category: resultCategoryProperty,
			Value:    value,
			Context:  "Vulnerability for " + target,
			Tags:     tags,
			Source:   src,
		})
	}
}

func extractBannerGeo(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, target string) {
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
		Type:     "geo",
		Category: resultCategoryProperty,
		Value:    strings.Join(geoParts, " | "),
		Context:  "Location for " + target,
		Tags:     tags,
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

func extractBannerHash(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, src *schema.EntityRef, target string) {
	if banner.Hash == 0 {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     "hash",
		Category: resultCategoryProperty,
		Value:    strconv.FormatInt(banner.Hash, 10),
		Context:  "Hash for " + target,
		Tags:     tags,
		Source:   src,
	})
}

func extractBannerTimestamp(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, src *schema.EntityRef, target string) {
	if banner.Timestamp == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultTypeBannerTimestamp,
		Category: resultCategoryProperty,
		Value:    banner.Timestamp,
		Context:  "Banner Timestamp for " + target,
		Tags:     tags,
		Source:   src,
	})
}

func extractBannerHeartbleed(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, src *schema.EntityRef, target string) {
	if banner.Heartbleed == "" {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultTypeHeartbleed,
		Category: resultCategoryProperty,
		Value:    banner.Heartbleed,
		Context:  "Heartbleed for " + target,
		Tags:     tags,
		Source:   src,
	})
}
