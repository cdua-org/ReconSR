package virustotal

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func extractPDFInfoParts(pdfInfo map[string]any, parts *[]string) {
	fields := []struct {
		key   string
		label string
	}{
		{"javascript", "JavaScript"},
		{"flash", "Flash"},
		{"acroform", "AcroForm"},
		{"autoaction", "AutoAction"},
		{"openaction", "OpenAction"},
		{"encrypted", "Encrypted"},
		{"embedded_file", "EmbeddedFiles"},
	}
	var extracted []string
	if header, ok := pdfInfo["header"].(string); ok && header != "" {
		extracted = append(extracted, "Header: "+header)
	}
	for _, f := range fields {
		if val, ok := pdfInfo[f.key].(float64); ok && val > 0 {
			extracted = append(extracted, fmt.Sprintf("%s: %d", f.label, int(val)))
		}
	}
	if len(extracted) > 0 {
		*parts = append(*parts, "PDF Info: "+strings.Join(extracted, ", "))
	}
}

func extractSignatureMetaParts(sigInfo map[string]any, parts *[]string) {
	fields := []struct {
		key   string
		label string
	}{
		{"original name", "Original Name"},
		{"product", "Product"},
		{"copyright", "Copyright"},
		{"description", "Description"},
		{"file version", "File Version"},
		{"internal name", "Internal Name"},
		{"TeamIdentifier", "Team ID"},
		{"Identifier", "App ID"},
		{"Authority", "Authority"},
	}

	for _, f := range fields {
		if val, ok := sigInfo[f.key].(string); ok && val != "" {
			*parts = append(*parts, fmt.Sprintf("%s: %s", f.label, val))
		}
	}
}

func extractAndroguardMetaParts(androguard map[string]any, parts *[]string) {
	if pkg, ok := androguard["Package"].(string); ok && pkg != "" {
		ver := ""
		if vName, ok := androguard["AndroidVersionName"].(string); ok && vName != "" {
			ver = " (v" + vName + ")"
		}
		*parts = append(*parts, "Android Package: "+pkg+ver)
	}
	if mainActivity, ok := androguard["main_activity"].(string); ok && mainActivity != "" {
		*parts = append(*parts, "Main Activity: "+mainActivity)
	}
	if minSDK, ok := androguard["MinSdkVersion"].(string); ok && minSDK != "" {
		*parts = append(*parts, "Min SDK: "+minSDK)
	}
	if targetSDK, ok := androguard["TargetSdkVersion"].(string); ok && targetSDK != "" {
		*parts = append(*parts, "Target SDK: "+targetSDK)
	}
}

func extractFileAnalyzerParts(attr map[string]any) []string {
	var parts []string

	extractFileAnalyzerVotes(attr, &parts)

	if packers, ok := attr["packers"].(map[string]any); ok {
		pList := make([]string, 0, len(packers))
		for k := range packers {
			pList = append(pList, k)
		}
		if len(pList) > 0 {
			parts = append(parts, "Packers: "+strings.Join(pList, ", "))
		}
	}
	if magika, ok := attr["magika"].(string); ok && magika != "" {
		parts = append(parts, "Magika: "+magika)
	}
	if detectiteasy, ok := attr["detectiteasy"].(map[string]any); ok {
		if filetype, ok := detectiteasy["filetype"].(string); ok && filetype != "" {
			parts = append(parts, "DetectItEasy: "+filetype)
		}
	}
	if androguard, ok := attr["androguard"].(map[string]any); ok {
		extractAndroguardAnalyzerParts(androguard, &parts)
	}
	extractIDSStatsParts(attr, &parts)
	return parts
}

func extractFileAnalyzerVotes(attr map[string]any, parts *[]string) {
	if times, ok := attr["times_submitted"].(float64); ok && times > 0 {
		*parts = append(*parts, fmt.Sprintf("Times Submitted: %d", int(times)))
	}
	if sources, ok := attr["unique_sources"].(float64); ok && sources > 0 {
		*parts = append(*parts, fmt.Sprintf("Unique Sources: %d", int(sources)))
	}
	if votes, ok := attr["total_votes"].(map[string]any); ok {
		var voteParts []string
		if harmless, ok := votes["harmless"].(float64); ok && harmless > 0 {
			voteParts = append(voteParts, fmt.Sprintf("Harmless: %d", int(harmless)))
		}
		if malicious, ok := votes["malicious"].(float64); ok && malicious > 0 {
			voteParts = append(voteParts, fmt.Sprintf("Malicious: %d", int(malicious)))
		}
		if len(voteParts) > 0 {
			*parts = append(*parts, "Community Votes: "+strings.Join(voteParts, ", "))
		}
	}
}

func extractAndroguardAnalyzerParts(androguard map[string]any, parts *[]string) {
	if permDetails, ok := androguard["permission_details"].(map[string]any); ok {
		extractDangerousPerms(permDetails, parts)
	}
}

func extractDangerousPerms(permDetails map[string]any, parts *[]string) {
	var dangerousPerms []string
	for permName, rawDetails := range permDetails {
		isDangerous := false
		if details, ok := rawDetails.(map[string]any); ok {
			if permType, ok := details["permission_type"].(string); ok && strings.Contains(strings.ToLower(permType), "dangerous") {
				isDangerous = true
			}
		} else if strVal, ok := rawDetails.(string); ok && strings.Contains(strings.ToLower(strVal), "dangerous") {
			isDangerous = true
		}
		if isDangerous {
			shortName := strings.TrimPrefix(permName, "android.permission.")
			dangerousPerms = append(dangerousPerms, shortName)
		}
	}
	if len(dangerousPerms) > 0 {
		sort.Strings(dangerousPerms)
		*parts = append(*parts, "Dangerous Permissions: "+strings.Join(dangerousPerms, ", "))
	}
}

func appendFileCertificates(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if sigInfo, ok := attr["signature_info"].(map[string]any); ok {
		if verified, ok := sigInfo["verified"].(string); ok && verified != "" {
			appendVTProperty(exec, constants.TypeStatus, verified, "Signature Status", hashRef, gen)
		}
		if signingDate, ok := sigInfo["signing date"].(string); ok && signingDate != "" {
			appendVTProperty(exec, constants.TypeDate, "Signed: "+signingDate, "Digital Signature", hashRef, gen)
		} else if timestamp, ok := sigInfo["Timestamp"].(string); ok && timestamp != "" {
			appendVTProperty(exec, constants.TypeDate, "Signed: "+timestamp, "Digital Signature", hashRef, gen)
		}
		extractX509Certificates(exec, sigInfo, hashRef, gen)
	}

	if androguard, ok := attr["androguard"].(map[string]any); ok {
		extractAndroguardCertificates(exec, androguard, hashRef, gen)
	}
}

func extractAndroguardCertificates(exec *schema.ModuleExecution, androguard map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	cert, ok := androguard["certificate"].(map[string]any)
	if !ok {
		return
	}
	tp, ok := cert["thumbprint"].(string)
	if !ok || tp == "" {
		return
	}

	tpVal := "sha1:" + tp
	tpID := gen.NextID()
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeCertFingerprint,
		Category: constants.CategoryProperty,
		Value:    tpVal,
		Context:  "Android APK Certificate",
		Source:   hashRef,
		LocalID:  tpID,
	})
	tpRef := &schema.EntityRef{Type: constants.TypeCertFingerprint, Value: tpVal, LocalID: tpID}

	if issuerMap, ok := cert["Issuer"].(map[string]any); ok {
		if dn, ok := issuerMap["DN"].(string); ok && dn != "" {
			appendVTProperty(exec, constants.TypeCertIssuer, dn, "Android APK Certificate", tpRef, gen)
		}
	}

	if validTo, ok := cert["validto"].(string); ok && validTo != "" {
		t, err := time.Parse("2006-01-02 15:04:05", validTo)
		if err == nil {
			appendVTProperty(exec, constants.TypeCertNotAfter, t.UTC().Format(time.RFC3339), "Android APK Certificate", tpRef, gen)
		} else {
			appendVTProperty(exec, constants.TypeCertNotAfter, validTo, "Android APK Certificate", tpRef, gen)
		}
	}
}

func mergeSignatureCertificates(sigInfo map[string]any) map[string]map[string]any {
	certMap := make(map[string]map[string]any)

	mergeCerts := func(list []any) {
		for _, item := range list {
			if cert, ok := item.(map[string]any); ok {
				if tp, ok := cert["thumbprint"].(string); ok && strings.TrimSpace(tp) != "" {
					tp = strings.ToUpper(strings.TrimSpace(tp))
					if existing, found := certMap[tp]; found {
						maps.Copy(existing, cert)
					} else {
						certMap[tp] = maps.Clone(cert)
					}
				}
			}
		}
	}

	if x509List, ok := sigInfo["x509"].([]any); ok {
		mergeCerts(x509List)
	}
	if signersList, ok := sigInfo["signers details"].([]any); ok {
		mergeCerts(signersList)
	}
	if counterList, ok := sigInfo["counter signers details"].([]any); ok {
		mergeCerts(counterList)
	}

	return certMap
}

func extractX509Certificates(exec *schema.ModuleExecution, sigInfo map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	certMap := mergeSignatureCertificates(sigInfo)

	if len(certMap) == 0 {
		return
	}

	var thumbprints []string
	for tp := range certMap {
		thumbprints = append(thumbprints, tp)
	}
	sort.Strings(thumbprints)

	for _, tp := range thumbprints {
		cert := certMap[tp]
		tpVal := "sha1:" + tp
		tpID := gen.NextID()
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCertFingerprint,
			Category: constants.CategoryProperty,
			Value:    tpVal,
			Context:  "Digital Signature",
			Source:   hashRef,
			LocalID:  tpID,
		})
		tpRef := &schema.EntityRef{Type: constants.TypeCertFingerprint, Value: tpVal, LocalID: tpID}

		if issuer, ok := cert["cert issuer"].(string); ok && issuer != "" {
			appendVTProperty(exec, constants.TypeCertIssuer, issuer, "Digital Signature", tpRef, gen)
		}
		if tp256, ok := cert["thumbprint_sha256"].(string); ok && tp256 != "" {
			appendVTProperty(exec, constants.TypeCertFingerprint, "sha256:"+tp256, "Digital Signature", tpRef, gen)
		}
		if validTo, ok := cert["valid to"].(string); ok && validTo != "" {
			t, err := time.Parse("2006-01-02 15:04:05", validTo)
			if err == nil {
				appendVTProperty(exec, constants.TypeCertNotAfter, t.UTC().Format(time.RFC3339), "Digital Signature", tpRef, gen)
			} else {
				appendVTProperty(exec, constants.TypeCertNotAfter, validTo, "Digital Signature", tpRef, gen)
			}
		}
		if name, ok := cert["name"].(string); ok && name != "" {
			appendVTProperty(exec, constants.TypeOrganization, name, "Digital Signature", tpRef, gen)
		}
		if status, ok := cert["status"].(string); ok && status != "" {
			appendVTProperty(exec, constants.TypeStatus, status, "Digital Signature", tpRef, gen)
		}
	}
}

func extractClassInfoParts(classInfo map[string]any, parts *[]string) {
	if name, ok := classInfo["name"].(string); ok && name != "" {
		*parts = append(*parts, "Class Name: "+name)
	}
	if platform, ok := classInfo["platform"].(string); ok && platform != "" {
		*parts = append(*parts, "Platform: "+platform)
	}
	if extends, ok := classInfo["extends"].(string); ok && extends != "" {
		*parts = append(*parts, "Extends: "+extends)
	}

	listFields := []struct {
		key   string
		label string
	}{
		{"implements", "Implements"},
		{"methods", "Methods"},
		{"constants", "Constants"},
		{"provides", "Provides"},
		{"requires", "Requires"},
	}

	for _, field := range listFields {
		if rawList, ok := classInfo[field.key].([]any); ok && len(rawList) > 0 {
			items := make([]string, 0, len(rawList))
			for _, v := range rawList {
				if str, ok := v.(string); ok && str != "" {
					items = append(items, str)
				}
			}
			if len(items) > 0 {
				*parts = append(*parts, field.label+": "+strings.Join(items, ", "))
			}
		}
	}
}
