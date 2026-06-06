package netlas

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/schema"
)

func parsePorts(exec *schema.ModuleExecution, ports []netlasPort, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) map[int]*schema.EntityRef {
	portRefs := make(map[int]*schema.EntityRef)
	for _, p := range ports {
		var val string
		if p.Prot4 != "" {
			val = fmt.Sprintf("%d/%s", p.Port, p.Prot4)
		} else {
			val = strconv.Itoa(p.Port)
		}

		label := p.Protocol
		if label != "" && p.Prot4 != "" {
			label = strings.TrimSuffix(label, "_"+p.Prot4)
		}
		if label == "" || label == p.Prot4 || label == "raw" {
			label = p.Prot7
		}
		if label != "" && label != "raw" && label != p.Prot4 {
			val += " " + label
		}

		portID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypePort,
			Category: constants.CategoryProperty,
			Value:    val,
			Context:  "Netlas Port",
			Source:   targetRef,
			LocalID:  portID,
		})

		portRefs[p.Port] = &schema.EntityRef{
			Type:    constants.TypePort,
			Value:   val,
			LocalID: portID,
		}
	}
	return portRefs
}

func parseSoftware(exec *schema.ModuleExecution, software []netlasSoftware, portRefs map[int]*schema.EntityRef, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	for i := range software {
		sw := &software[i]
		pRef := targetRef

		if sw.URI != "" {
			port := extractPortFromURI(sw.URI)
			if port > 0 {
				if r, exists := portRefs[port]; exists {
					pRef = r
				}
			}
		}

		serviceRefs := parseSoftwareTags(exec, sw, pRef, gen)
		parseSoftwareCVEs(exec, sw, serviceRefs, pRef, targetRef, gen)
	}
}

func parseSoftwareTags(exec *schema.ModuleExecution, sw *netlasSoftware, pRef *schema.EntityRef, gen *modutil.LocalIDGenerator) map[string]*schema.EntityRef {
	serviceRefs := make(map[string]*schema.EntityRef)
	cpeRefs := make(map[string]*schema.EntityRef)

	for _, tag := range sw.Tags {
		if tag.FullName == "" && tag.Name == "" {
			continue
		}
		val := tag.FullName
		if val == "" {
			val = tag.Name
		}
		if tag.Version != "" {
			val += " " + tag.Version
		}

		sRef := findExistingServiceByCPE(tag.CPE, cpeRefs)
		if sRef == nil {
			sRef = emitNewService(exec, &tag, val, pRef, gen)
		}

		for _, cpe := range tag.CPE {
			if _, exists := cpeRefs[cpe]; !exists {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     constants.TypeCPE,
					Category: constants.CategoryProperty,
					Value:    cpe,
					Source:   sRef,
					LocalID:  gen.NextID(),
				})
				cpeRefs[cpe] = sRef
			}
		}

		if tag.Version != "" {
			serviceRefs[strings.ToLower(val)] = sRef
			if tag.Name != "" {
				serviceRefs[strings.ToLower(tag.Name+" "+tag.Version)] = sRef
			}
			if tag.FullName != "" {
				serviceRefs[strings.ToLower(tag.FullName+" "+tag.Version)] = sRef
			}
		}
	}

	return serviceRefs
}

func findExistingServiceByCPE(cpes []string, cpeRefs map[string]*schema.EntityRef) *schema.EntityRef {
	for _, cpe := range cpes {
		if ref, ok := cpeRefs[cpe]; ok {
			return ref
		}
	}
	return nil
}

func emitNewService(exec *schema.ModuleExecution, tag *netlasSoftwareTag, val string, pRef *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	serviceID := gen.NextID()

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeService,
		Category: constants.CategoryProperty,
		Value:    val,
		Tags:     make([]string, 0),
		Source:   pRef,
		LocalID:  serviceID,
	})

	sRef := &schema.EntityRef{Type: constants.TypeService, Value: val, LocalID: serviceID}

	if tag.Description != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDescription,
			Category: constants.CategoryProperty,
			Value:    strings.Join(strings.Fields(tag.Description), " "),
			Source:   sRef,
			LocalID:  gen.NextID(),
		})
	}

	for _, cat := range tag.Category {
		if strings.EqualFold(cat, "database") {
			continue
		}
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCategory,
			Category: constants.CategoryProperty,
			Value:    cat,
			Source:   sRef,
			LocalID:  gen.NextID(),
		})
	}
	return sRef
}

func parseSoftwareCVEs(exec *schema.ModuleExecution, sw *netlasSoftware, serviceRefs map[string]*schema.EntityRef, pRef, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	hasVulns := false
	for i := range sw.CVE {
		cve := &sw.CVE[i]
		if cve.Name == "" || cve.MatchType != "cpe" {
			continue
		}
		hasVulns = true

		cveID := gen.NextID()
		cveRef := &schema.EntityRef{Type: constants.TypeCVE, Value: cve.Name, LocalID: cveID}

		cveParent := pRef
		if cve.MatchProduct != "" {
			lookup := strings.ToLower(cve.MatchProduct)
			if ref, ok := serviceRefs[lookup]; ok {
				cveParent = ref
			} else {
				continue
			}
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVE,
			Category: constants.CategoryProperty,
			Value:    cve.Name,
			Source:   cveParent,
			LocalID:  cveID,
		})

		if cve.Description != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeSummary,
				Category: constants.CategoryProperty,
				Value:    strings.Join(strings.Fields(cve.Description), " "),
				Source:   cveRef,
				LocalID:  gen.NextID(),
			})
		}

		cvssRef := extractCVSS(exec, cve, cveRef, gen)

		if cve.Published != "" {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeDate,
				Category: constants.CategoryProperty,
				Value:    "Published: " + cve.Published,
				Source:   cveRef,
				LocalID:  gen.NextID(),
			})
		}

		extractCVEMetrics(exec, cve, cvssRef, gen)

		for _, link := range cve.ExploitLinks {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeExploit,
				Category: constants.CategoryProperty,
				Value:    link,
				Source:   cveRef,
				LocalID:  gen.NextID(),
			})
		}
	}

	if hasVulns && targetRef != nil {
		addSystemTagToNode(exec, targetRef, constants.TagCVE, gen)
	}
}

func extractCVSS(exec *schema.ModuleExecution, cve *netlasCVE, cveRef *schema.EntityRef, gen *modutil.LocalIDGenerator) *schema.EntityRef {
	var cvssRef *schema.EntityRef
	switch {
	case cve.Severity != nil && cve.BaseScore != nil:
		cvssID := gen.NextID()
		cvssVal := fmt.Sprintf("%v / %v", cve.Severity, cve.BaseScore)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVSS,
			Category: constants.CategoryProperty,
			Value:    cvssVal,
			Source:   cveRef,
			LocalID:  cvssID,
		})
		cvssRef = &schema.EntityRef{Type: constants.TypeCVSS, Value: cvssVal, LocalID: cvssID}
	case cve.Severity != nil:
		cvssID := gen.NextID()
		cvssVal := fmt.Sprintf("%v", cve.Severity)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVSS,
			Category: constants.CategoryProperty,
			Value:    cvssVal,
			Context:  "Severity",
			Source:   cveRef,
			LocalID:  cvssID,
		})
		cvssRef = &schema.EntityRef{Type: constants.TypeCVSS, Value: cvssVal, LocalID: cvssID}
	case cve.BaseScore != nil:
		cvssID := gen.NextID()
		cvssVal := fmt.Sprintf("%v", cve.BaseScore)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVSS,
			Category: constants.CategoryProperty,
			Value:    cvssVal,
			Context:  "Base Score",
			Source:   cveRef,
			LocalID:  cvssID,
		})
		cvssRef = &schema.EntityRef{Type: constants.TypeCVSS, Value: cvssVal, LocalID: cvssID}
	}

	if cvssRef == nil && (cve.AttackVector != "" || cve.AttackComplexity != "" || cve.PrivilegesRequired != "" || cve.UserInteraction != "" || cve.ConfidentialityImpact != "" || cve.IntegrityImpact != "" || cve.AvailabilityImpact != "") {
		cvssID := gen.NextID()
		cvssVal := "Metrics Available"
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCVSS,
			Category: constants.CategoryProperty,
			Value:    cvssVal,
			Source:   cveRef,
			LocalID:  cvssID,
		})
		cvssRef = &schema.EntityRef{Type: constants.TypeCVSS, Value: cvssVal, LocalID: cvssID}
	}

	if cvssRef == nil {
		cvssRef = cveRef
	}
	return cvssRef
}

func extractCVEMetrics(exec *schema.ModuleExecution, cve *netlasCVE, cveRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if cve.AttackVector != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeAttackVector,
			Category: constants.CategoryProperty,
			Value:    cve.AttackVector,
			Source:   cveRef,
			LocalID:  gen.NextID(),
		})
	}

	if cve.AttackComplexity != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeAttackComplexity,
			Category: constants.CategoryProperty,
			Value:    cve.AttackComplexity,
			Source:   cveRef,
			LocalID:  gen.NextID(),
		})
	}

	if cve.PrivilegesRequired != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypePrivilegesRequired,
			Category: constants.CategoryProperty,
			Value:    cve.PrivilegesRequired,
			Source:   cveRef,
			LocalID:  gen.NextID(),
		})
	}

	if cve.UserInteraction != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeUserInteraction,
			Category: constants.CategoryProperty,
			Value:    cve.UserInteraction,
			Source:   cveRef,
			LocalID:  gen.NextID(),
		})
	}

	if cve.ConfidentialityImpact != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeConfidentialityImpact,
			Category: constants.CategoryProperty,
			Value:    cve.ConfidentialityImpact,
			Source:   cveRef,
			LocalID:  gen.NextID(),
		})
	}

	if cve.IntegrityImpact != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeIntegrityImpact,
			Category: constants.CategoryProperty,
			Value:    cve.IntegrityImpact,
			Source:   cveRef,
			LocalID:  gen.NextID(),
		})
	}

	if cve.AvailabilityImpact != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeAvailabilityImpact,
			Category: constants.CategoryProperty,
			Value:    cve.AvailabilityImpact,
			Source:   cveRef,
			LocalID:  gen.NextID(),
		})
	}
}

func parseIoC(exec *schema.ModuleExecution, iocs []netlasIoC, targetRef *schema.EntityRef, mainASNs []string, gen *modutil.LocalIDGenerator) {
	for i := range iocs {
		parseIoCItem(exec, &iocs[i], targetRef, mainASNs, gen)
	}
}

func parseIoCItem(exec *schema.ModuleExecution, ioc *netlasIoC, targetRef *schema.EntityRef, mainASNs []string, gen *modutil.LocalIDGenerator) {
	infoID := gen.NextID()

	val := ioc.Timestamp
	if val == "" {
		val = "Unknown Date"
	} else if len(val) >= 10 && val[4] == '-' && val[7] == '-' {
		val = val[0:4] + "/" + val[5:7] + "/" + val[8:10]
	}

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeIoCRecord,
		Category: constants.CategoryProperty,
		Value:    val,
		Source:   targetRef,
		LocalID:  infoID,
	})
	parentRef := &schema.EntityRef{Type: constants.TypeIoCRecord, Value: val, LocalID: infoID}

	if ioc.URL != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeThreatURL,
			Category: constants.CategoryProperty,
			Value:    ioc.URL,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}

	extractIoCMetadata(exec, ioc, parentRef, mainASNs, gen)
	parseIoCFalsePositive(exec, ioc, parentRef, gen)
	parseIoCTags(exec, ioc, parentRef, targetRef, gen)
}

func parseIoCFalsePositive(exec *schema.ModuleExecution, ioc *netlasIoC, parentRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if ioc.FP != nil && ioc.FP.Alarm != "" && ioc.FP.Alarm != "false" {
		alarmType := "False Positive"
		switch ioc.FP.Alarm {
		case "true":
			alarmType = "Confirmed False Positive"
		case "possible":
			alarmType = "Possible False Positive"
		}

		val := alarmType
		if ioc.FP.Descr != "" {
			val += ": " + ioc.FP.Descr
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeInfo,
			Category: constants.CategoryProperty,
			Value:    val,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}
}

func extractIoCMetadata(exec *schema.ModuleExecution, ioc *netlasIoC, parentRef *schema.EntityRef, mainASNs []string, gen *modutil.LocalIDGenerator) {
	if ioc.Score != nil {
		scoreStr := fmt.Sprintf("Score: %.2f (Source Trust: %.2f | Severity Weight: %.2f | Activity Recency: %.2f)",
			ioc.Score.Total, ioc.Score.Src, ioc.Score.Tags, ioc.Score.Frequency)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeThreatScore,
			Category: constants.CategoryProperty,
			Value:    scoreStr,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}

	if ioc.FirstSeen != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "First Seen: " + ioc.FirstSeen,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}

	if ioc.LastSeen != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeDate,
			Category: constants.CategoryProperty,
			Value:    "Last Seen: " + ioc.LastSeen,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}

	if ioc.ISP != "" {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeISP,
			Category: constants.CategoryProperty,
			Value:    ioc.ISP,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}

	if ioc.ASN > 0 {
		asnStr := fmt.Sprintf("AS%d", ioc.ASN)
		isMain := false
		for _, m := range mainASNs {
			if "AS"+m == asnStr {
				isMain = true
				break
			}
		}
		if !isMain {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeASN,
				Category: constants.CategoryNode,
				Value:    asnStr,
				Source:   parentRef,
				LocalID:  gen.NextID(),
			})
		}
	}

	for _, port := range ioc.Ports {
		if port > 0 {
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypePort,
				Category: constants.CategoryProperty,
				Value:    strconv.Itoa(port),
				Source:   parentRef,
				LocalID:  gen.NextID(),
			})
		}
	}
}

func parseNetlasDomains(exec *schema.ModuleExecution, count int, domains []string, systemTag string, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if count <= 0 || count > 10 {
		return
	}
	for _, d := range domains {
		if d == "" {
			continue
		}
		if valDomain, err := validator.Validate(constants.TypeDomain, d); err == nil {
			var tags []string
			if systemTag != "" {
				tags = append(tags, systemTag)
			}
			outOfScope := false
			if targetRef.Type == constants.TypeDomain {
				outOfScope = orgdomain.IsOutOfScope(valDomain.Value, targetRef.Value)
			}
			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:       constants.TypeDomain,
				Category:   constants.CategoryNode,
				Value:      valDomain.Value,
				Tags:       tags,
				Source:     targetRef,
				LocalID:    gen.NextID(),
				OutOfScope: outOfScope,
			})
		}
	}
}

func parseIoCTags(exec *schema.ModuleExecution, ioc *netlasIoC, parentRef, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	isFalsePositive := ioc.FP != nil && ioc.FP.Alarm != "" && ioc.FP.Alarm != "false"
	isHighRisk := true
	if ioc.Score != nil {
		isHighRisk = ioc.Score.Total >= 55.0
	}

	for _, t := range ioc.Tags {
		if t == "" {
			continue
		}

		if !isFalsePositive && isHighRisk {
			switch t {
			case "malware":
				addSystemTagToNode(exec, targetRef, constants.TagMalware, gen)
			case "malicious":
				addSystemTagToNode(exec, targetRef, constants.TagMalicious, gen)
			case "compromised":
				addSystemTagToNode(exec, targetRef, constants.TagCompromised, gen)
			case "suspicious":
				addSystemTagToNode(exec, targetRef, constants.TagSuspicious, gen)
			case "phishing":
				addSystemTagToNode(exec, targetRef, constants.TagPhishing, gen)
			}
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeThreatType,
			Category: constants.CategoryProperty,
			Value:    t,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}

	for _, t := range ioc.Threat {
		if t == "" {
			continue
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeRelatedThreat,
			Category: constants.CategoryProperty,
			Value:    t,
			Source:   parentRef,
			LocalID:  gen.NextID(),
		})
	}
}

func parseGeo(exec *schema.ModuleExecution, geo *netlasGeo, gen *modutil.LocalIDGenerator) {
	if geo == nil {
		return
	}
	parts := make([]string, 0)
	if geo.City != "" {
		parts = append(parts, "City: "+geo.City)
	}
	if len(geo.Subdivisions) > 0 {
		parts = append(parts, "Region: "+strings.Join(geo.Subdivisions, ", "))
	}
	if geo.Country != "" {
		parts = append(parts, "Country: "+geo.Country)
	} else if geo.RegisteredCountry != "" {
		parts = append(parts, "Country: "+geo.RegisteredCountry)
	}
	if geo.Continent != "" {
		parts = append(parts, "Continent: "+geo.Continent)
	}

	if geo.Location != nil {
		parts = append(parts, fmt.Sprintf("Lat/Lon: %f, %f", geo.Location.Lat, geo.Location.Lon))
	}
	if geo.Accuracy > 0 {
		parts = append(parts, fmt.Sprintf("Accuracy: %d", geo.Accuracy))
	}

	if len(parts) > 0 {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeGeo,
			Category: constants.CategoryProperty,
			Value:    strings.Join(parts, " | "),
			Context:  "Geo Location",
			LocalID:  gen.NextID(),
		})
	}
}

func extractPortFromURI(uri string) int {
	parts := strings.Split(uri, ":")
	if len(parts) >= 3 {
		p := parts[2]
		if idx := strings.Index(p, "/"); idx != -1 {
			p = p[:idx]
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return 0
		}
		return port
	}
	return 0
}

func addSystemTagToNode(exec *schema.ModuleExecution, targetRef *schema.EntityRef, tag string, gen *modutil.LocalIDGenerator) {
	if targetRef == nil {
		return
	}
	for i, r := range exec.Results {
		if r.Category == constants.CategoryNode && r.Value == targetRef.Value && r.Type == targetRef.Type {
			if !slices.Contains(r.Tags, tag) {
				exec.Results[i].Tags = append(exec.Results[i].Tags, tag)
			}
			return
		}
	}
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     targetRef.Type,
		Category: constants.CategoryNode,
		Value:    targetRef.Value,
		Tags:     []string{tag},
		LocalID:  gen.NextID(),
	})
}
