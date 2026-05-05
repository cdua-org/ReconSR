package shodan

import (
	"fmt"
	"strconv"
	"strings"

	"cdua-org/ReconSR/schema"
)

func extractIPBanners(exec *schema.ModuleExecution, banners []shodanIPBanner, tags []string) {
	for i := range banners {
		banner := &banners[i]
		portSrc := extractBannerPort(exec, banner, tags)
		src := extractBannerSource(exec, banner, tags, portSrc)
		extractBannerSSL(exec, banner, tags)
		extractBannerCPEs(exec, banner, tags, src)
		extractBannerVulns(exec, banner, tags, src)
		extractBannerGeo(exec, banner, tags)
		extractBannerHash(exec, banner, tags, src)
	}
}

func extractBannerPort(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string) *schema.EntityRef {
	if banner.Port == 0 {
		return nil
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
		Tags:     tags,
	})

	return &schema.EntityRef{Type: resultTypePort, Value: portValue}
}

func extractBannerSource(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, portSrc *schema.EntityRef) *schema.EntityRef {
	serviceValue := extractBannerServiceValue(banner)
	webServerValue := extractBannerWebServerValue(banner)

	switch {
	case serviceValue != "" && webServerValue != "" && serviceValue == webServerValue:
		return appendBannerSourceResult(exec, resultTypeWebServer, webServerValue, tags, portSrc)
	case serviceValue != "":
		src := appendBannerSourceResult(exec, resultTypeService, serviceValue, tags, portSrc)
		if webServerValue != "" {
			appendBannerSourceResult(exec, resultTypeWebServer, webServerValue, tags, src)
		}
		return src
	case webServerValue != "":
		return appendBannerSourceResult(exec, resultTypeWebServer, webServerValue, tags, portSrc)
	default:
		return portSrc
	}
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

func appendBannerSourceResult(exec *schema.ModuleExecution, resultType, value string, tags []string, src *schema.EntityRef) *schema.EntityRef {
	if value == "" {
		return nil
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     resultType,
		Category: resultCategoryProperty,
		Value:    value,
		Tags:     tags,
		Source:   src,
	})

	return &schema.EntityRef{Type: resultType, Value: value}
}

func extractBannerCPEs(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, src *schema.EntityRef) {
	if banner.Artifacts == nil {
		return
	}

	appendBannerStringResults(exec, resultTypeCPE, banner.Artifacts.CPE, tags, src)
	appendBannerStringResults(exec, "cpe23", banner.Artifacts.CPE23, tags, src)
}

func appendBannerStringResults(exec *schema.ModuleExecution, resultType string, values, tags []string, src *schema.EntityRef) {
	for _, value := range values {
		if value == "" {
			continue
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     resultType,
			Category: resultCategoryProperty,
			Value:    value,
			Tags:     tags,
			Source:   src,
		})
	}
}

func extractBannerVulns(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, src *schema.EntityRef) {
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
			Tags:     tags,
			Source:   src,
		})
	}
}

func extractBannerGeo(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string) {
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

func extractBannerHash(exec *schema.ModuleExecution, banner *shodanIPBanner, tags []string, src *schema.EntityRef) {
	if banner.Hash == 0 {
		return
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     "hash",
		Category: resultCategoryProperty,
		Value:    strconv.FormatInt(banner.Hash, 10),
		Tags:     tags,
		Source:   src,
	})
}
