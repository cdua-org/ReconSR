package virustotal

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func appendFileHashes(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	hashFields := []struct {
		key    string
		prefix string
	}{
		{constants.KeyMD5, constants.KeyMD5},
		{constants.KeySHA1, constants.KeySHA1},
		{"ssdeep", "ssdeep"},
		{"vhash", "vhash"},
		{"authentihash", "authentihash"},
		{"tlsh", "tlsh"},
		{"permhash", "permhash"},
	}
	for _, h := range hashFields {
		if val, ok := attr[h.key].(string); ok && val != "" {
			appendVTProperty(exec, constants.TypeFileHash, h.prefix+":"+val, "", hashRef, gen)
		}
	}

	if peInfo, ok := attr["pe_info"].(map[string]any); ok {
		if imphash, ok := peInfo["imphash"].(string); ok && imphash != "" {
			appendVTProperty(exec, constants.TypeFileHash, "imphash:"+imphash, "", hashRef, gen)
		}
	}
}

func appendFileName(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	uniqueNames := make(map[string]bool)

	if name, ok := attr["meaningful_name"].(string); ok && name != "" {
		uniqueNames[name] = true
	}
	if names, ok := attr["names"].([]any); ok {
		for _, n := range names {
			if strName, ok := n.(string); ok && strName != "" {
				uniqueNames[strName] = true
			}
		}
	}

	for nameStr := range uniqueNames {
		if unescaped, err := url.QueryUnescape(nameStr); err == nil {
			nameStr = unescaped
		}
		appendVTProperty(exec, constants.TypeFileName, nameStr, "", hashRef, gen)
	}
}

func extractFileInfoParts(attr map[string]any) []string {
	var parts []string
	if typeDesc, ok := attr["type_description"].(string); ok && typeDesc != "" {
		parts = append(parts, "Type: "+typeDesc)
	}
	if sizeVal, ok := attr["size"].(float64); ok {
		parts = append(parts, fmt.Sprintf("Size: %d bytes", int64(sizeVal)))
	}
	if typeTags, ok := attr["type_tags"].([]any); ok {
		tags := make([]string, 0, len(typeTags))
		for _, t := range typeTags {
			if s, ok := t.(string); ok && s != "" {
				tags = append(tags, s)
			}
		}
		if len(tags) > 0 {
			parts = append(parts, "Tags: "+strings.Join(tags, ", "))
		}
	}
	return parts
}

func extractFileMetaParts(attr map[string]any, exec *schema.ModuleExecution, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) []string {
	var parts []string
	if sigInfo, ok := attr["signature_info"].(map[string]any); ok {
		extractSignatureMetaParts(sigInfo, &parts)
	}
	if androguard, ok := attr["androguard"].(map[string]any); ok {
		extractAndroguardMetaParts(androguard, &parts)
	}
	if pdfInfo, ok := attr["pdf_info"].(map[string]any); ok {
		extractPDFInfoParts(pdfInfo, &parts)
	}
	if bundleInfo, ok := attr["bundle_info"].(map[string]any); ok {
		extractBundleInfoParts(bundleInfo, exec, hashRef, gen)
	}
	if classInfo, ok := attr["class_info"].(map[string]any); ok {
		extractClassInfoParts(classInfo, &parts)
	}
	return parts
}

func extractBundleInfoParts(bundleInfo map[string]any, exec *schema.ModuleExecution, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	var bundleParts []string

	extractBundleInfoStrings(bundleInfo, &bundleParts, exec, hashRef, gen)
	extractBundleInfoNumbers(bundleInfo, &bundleParts)
	extractBundleInfoDates(bundleInfo, &bundleParts)
	extractBundleInfoMaps(bundleInfo, &bundleParts)

	if len(bundleParts) > 0 {
		val := strings.Join(bundleParts, " | ")
		appendVTProperty(exec, constants.TypeBundleInfo, val, "", hashRef, gen)
	}
}

func extractBundleInfoStrings(bundleInfo map[string]any, parts *[]string, exec *schema.ModuleExecution, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if typ, ok := bundleInfo["type"].(string); ok && typ != "" {
		*parts = append(*parts, "Bundle Type: "+typ)
	}
	if errMsg, ok := bundleInfo["error"].(string); ok && errMsg != "" {
		*parts = append(*parts, "Error: "+errMsg)
	}
	if beg, ok := bundleInfo["beginning"].(string); ok && beg != "" {
		*parts = append(*parts, "Beginning: "+beg)
	}
	if pwd, ok := bundleInfo["password"].(string); ok && pwd != "" {
		appendVTProperty(exec, constants.TypePassword, pwd, "Bundle Info", hashRef, gen)
	}
}

func extractBundleInfoNumbers(bundleInfo map[string]any, parts *[]string) {
	if num, ok := bundleInfo["num_children"].(float64); ok {
		*parts = append(*parts, fmt.Sprintf("Files: %d", int(num)))
	}
	if size, ok := bundleInfo["uncompressed_size"].(float64); ok {
		*parts = append(*parts, fmt.Sprintf("Uncompressed Size: %d", int(size)))
	}
}

func extractBundleInfoDates(bundleInfo map[string]any, parts *[]string) {
	if highest, ok := bundleInfo["highest_datetime"].(string); ok && highest != "" {
		*parts = append(*parts, "Newest File: "+highest)
	}
	if lowest, ok := bundleInfo["lowest_datetime"].(string); ok && lowest != "" {
		*parts = append(*parts, "Oldest File: "+lowest)
	}
}

func extractBundleInfoMaps(bundleInfo map[string]any, parts *[]string) {
	if extensions, ok := bundleInfo["extensions"].(map[string]any); ok && len(extensions) > 0 {
		var extParts []string
		for k, v := range extensions {
			if count, ok := v.(float64); ok {
				extParts = append(extParts, fmt.Sprintf("%s (%d)", k, int(count)))
			}
		}
		if len(extParts) > 0 {
			sort.Strings(extParts)
			*parts = append(*parts, "Extensions: "+strings.Join(extParts, ", "))
		}
	}
	if fileTypes, ok := bundleInfo["file_types"].(map[string]any); ok && len(fileTypes) > 0 {
		var typeParts []string
		for k, v := range fileTypes {
			if count, ok := v.(float64); ok {
				typeParts = append(typeParts, fmt.Sprintf("%s (%d)", k, int(count)))
			}
		}
		if len(typeParts) > 0 {
			sort.Strings(typeParts)
			*parts = append(*parts, "File Types: "+strings.Join(typeParts, ", "))
		}
	}
}

func appendFileInfo(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if parts := extractFileInfoParts(attr); len(parts) > 0 {
		appendVTProperty(exec, constants.TypeFileInfo, strings.Join(parts, " | "), "", hashRef, gen)
	}
	if parts := extractFileMetaParts(attr, exec, hashRef, gen); len(parts) > 0 {
		appendVTProperty(exec, constants.TypeFileMeta, strings.Join(parts, " | "), "", hashRef, gen)
	}
	if parts := extractFileAnalyzerParts(attr); len(parts) > 0 {
		appendVTProperty(exec, constants.TypeFileAnalyzer, strings.Join(parts, " | "), "", hashRef, gen)
	}
}

func appendFileDates(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	dateFields := []struct {
		key    string
		prefix string
	}{
		{"first_submission_date", "First Submission"},
		{"last_submission_date", "Last Submission"},
		{"last_analysis_date", "Last Analysis"},
		{"last_modification_date", "Last Modification"},
		{"creation_date", "Creation Date"},
	}

	for _, f := range dateFields {
		if tsVal, ok := attr[f.key].(float64); ok && tsVal > 0 {
			formatted := time.Unix(int64(tsVal), 0).UTC().Format(time.DateTime)
			appendVTProperty(exec, constants.TypeDate, f.prefix+": "+formatted, "", hashRef, gen)
		}
	}
}

func appendFileMagic(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	if magic, ok := attr["magic"].(string); ok && magic != "" {
		appendVTProperty(exec, constants.TypeFileMagic, magic, "", hashRef, gen)
	}
}

func appendFileDebInfo(exec *schema.ModuleExecution, attr map[string]any, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	debInfo, ok := attr["deb_info"].(map[string]any)
	if !ok {
		return
	}

	var parts []string
	var author, maintainer, vendor, homepage, pkgName string

	extractDebControlMetadata(debInfo, exec, hashRef, gen, &parts, &maintainer, &vendor, &homepage, &pkgName)
	extractDebChangelog(debInfo, exec, hashRef, gen, &parts, &author, pkgName)
	extractDebContacts(&parts, author, maintainer, vendor, homepage)
	extractDebStructuralMetadata(debInfo, exec, hashRef, gen, &parts)

	if len(parts) > 0 {
		appendVTProperty(exec, constants.TypePackageInfo, strings.Join(parts, " | "), "", hashRef, gen)
	}

	extractDebScripts(debInfo, exec, hashRef, gen)
}

func extractDebControlMetadata(debInfo map[string]any, exec *schema.ModuleExecution, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator, parts *[]string, maintainer, vendor, homepage, pkgName *string) {
	controlMetadata, ok := debInfo["control_metadata"].(map[string]any)
	if !ok {
		return
	}

	if pkg, ok := controlMetadata["Package"].(string); ok && pkg != "" {
		*pkgName = pkg
		appendVTProperty(exec, constants.TypeFileName, pkg, "", hashRef, gen)
	}

	if version, ok := controlMetadata["Version"].(string); ok && version != "" {
		versionStr := "Version: " + version
		if arch, ok := controlMetadata["Architecture"].(string); ok && arch != "" {
			versionStr += " (" + arch + ")"
		}
		*parts = append(*parts, versionStr)
	}

	if m, ok := controlMetadata["Maintainer"].(string); ok && m != "" {
		*maintainer = m
	}
	if v, ok := controlMetadata["Vendor"].(string); ok && v != "" {
		*vendor = v
	}
	if hp, ok := controlMetadata["Homepage"].(string); ok && hp != "" {
		*homepage = hp
	}
}

func extractDebChangelog(debInfo map[string]any, exec *schema.ModuleExecution, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator, parts *[]string, author *string, pkgName string) {
	changelog, ok := debInfo["changelog"].(map[string]any)
	if !ok {
		return
	}

	if urgency, ok := changelog["Urgency"].(string); ok && urgency != "" {
		*parts = append(*parts, "Urgency: "+urgency)
	}
	if a, ok := changelog["Author"].(string); ok && a != "" {
		*author = a
	}

	if dateStr, ok := changelog["Date"].(string); ok && dateStr != "" {
		if t, err := time.Parse(time.RFC1123Z, dateStr); err == nil {
			appendVTProperty(exec, constants.TypeDate, "Build: "+t.UTC().Format(time.DateTime), "", hashRef, gen)
		} else if t, err := time.Parse("Mon, 2 Jan 2006 15:04:05 -0700", dateStr); err == nil {
			appendVTProperty(exec, constants.TypeDate, "Build: "+t.UTC().Format(time.DateTime), "", hashRef, gen)
		} else if t, err := time.Parse(time.RFC1123, dateStr); err == nil {
			appendVTProperty(exec, constants.TypeDate, "Build: "+t.UTC().Format(time.DateTime), "", hashRef, gen)
		} else {
			appendVTProperty(exec, constants.TypeDate, "Build: "+dateStr, "", hashRef, gen)
		}
	}

	if pkgName == "" {
		if pkg, ok := changelog["Package"].(string); ok && pkg != "" {
			appendVTProperty(exec, constants.TypeFileName, pkg, "", hashRef, gen)
		}
	}
}

func extractDebContacts(parts *[]string, author, maintainer, vendor, homepage string) {
	contactRoles := make(map[string][]string)
	if author != "" {
		contactRoles[author] = append(contactRoles[author], "Author")
	}
	if maintainer != "" {
		contactRoles[maintainer] = append(contactRoles[maintainer], "Maintainer")
	}
	if vendor != "" {
		contactRoles[vendor] = append(contactRoles[vendor], "Vendor")
	}

	contacts := make([]string, 0, len(contactRoles))
	for contact, roles := range contactRoles {
		sort.Strings(roles)
		contacts = append(contacts, strings.Join(roles, "/")+": "+contact)
	}
	if len(contacts) > 0 {
		sort.Strings(contacts)
		*parts = append(*parts, contacts...)
	}

	if homepage != "" {
		*parts = append(*parts, "Homepage: "+homepage)
	}
}

func extractDebStructuralMetadata(debInfo map[string]any, exec *schema.ModuleExecution, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator, parts *[]string) {
	structuralMetadata, ok := debInfo["structural_metadata"].(map[string]any)
	if !ok {
		return
	}

	var structParts []string
	if files, ok := structuralMetadata["contained_items"].(float64); ok {
		structParts = append(structParts, fmt.Sprintf("Files: %d", int(files)))
	} else if files, ok := structuralMetadata["contained_files"].(float64); ok {
		structParts = append(structParts, fmt.Sprintf("Files: %d", int(files)))
	}

	var dates []string
	if minDate, ok := structuralMetadata["min_date"].(string); ok && minDate != "" {
		dates = append(dates, "Oldest: "+minDate)
		appendVTProperty(exec, constants.TypeDate, "Oldest Contained File: "+minDate, "", hashRef, gen)
	}
	if maxDate, ok := structuralMetadata["max_date"].(string); ok && maxDate != "" {
		dates = append(dates, "Newest: "+maxDate)
		appendVTProperty(exec, constants.TypeDate, "Newest Contained File: "+maxDate, "", hashRef, gen)
	}

	if len(structParts) > 0 {
		if len(dates) > 0 {
			*parts = append(*parts, structParts[0]+" ("+strings.Join(dates, ", ")+")")
		} else {
			*parts = append(*parts, structParts[0])
		}
	}
}

func extractDebScripts(debInfo map[string]any, exec *schema.ModuleExecution, hashRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	controlScripts, ok := debInfo["control_scripts"].(map[string]any)
	if !ok {
		return
	}
	var scriptNames []string
	for k := range controlScripts {
		scriptNames = append(scriptNames, k)
	}
	sort.Strings(scriptNames)
	for _, scriptName := range scriptNames {
		if scriptContent, ok := controlScripts[scriptName].(string); ok && scriptContent != "" {
			formatted := strings.ReplaceAll(scriptContent, "\n", `\n`)
			runes := []rune(formatted)
			if len(runes) > 150 {
				formatted = string(runes[:146]) + "..."
			}

			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     constants.TypeFileScript,
				Category: constants.CategoryProperty,
				Value:    formatted,
				Tags:     []string{scriptName},
				Source:   hashRef,
				LocalID:  gen.NextID(),
			})
		}
	}
}
