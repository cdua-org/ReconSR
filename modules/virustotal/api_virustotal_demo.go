package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func (m *module) processDomainDemo(_ context.Context, target string, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	if !m.demoDomainFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetVTApiDomain, target)
		return
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncGetVTApiDomain)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for VirusTotal (API key not configured)",
		LocalID:  gen.NextID(),
	})

	dataBytes, err := os.ReadFile("modules/virustotal/testdata/domain_page1.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return
	}
	modutil.SetRawFromBytes(exec, dataBytes)

	var data map[string]any
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		modutil.SetError(exec, "unmarshal fixture err: %v", err)
		return
	}

	if dataMap, ok := data["data"].(map[string]any); ok {
		if attr, ok := dataMap["attributes"].(map[string]any); ok {
			m.extractDomainMetadata(attr, target, exec, gen)
		}
	}

	disableCertExpired := false

	var expiredDomains []string

	for _, i := range []int{1, 2} {
		fixture := fmt.Sprintf("subdomains_page%d.json", i)
		fixturePath := filepath.Join("modules", "virustotal", "testdata", filepath.Clean(fixture))
		subDataBytes, err := os.ReadFile(filepath.Clean(fixturePath))
		if err != nil {
			continue
		}
		exec.RawData += "\n---\n" + string(subDataBytes)

		var subData map[string]any
		if err := json.Unmarshal(subDataBytes, &subData); err != nil {
			continue
		}

		items, ok := subData["data"].([]any)
		if !ok {
			continue
		}

		for _, item := range items {
			itemMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if expired := m.extractSubdomain(itemMap, target, disableCertExpired, exec, gen); expired != "" {
				expiredDomains = append(expiredDomains, expired)
			}
		}
	}

	if len(expiredDomains) > 0 {
		sort.Strings(expiredDomains)
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeCertExpiredSubdomains,
			Category: constants.CategoryProperty,
			Value:    strings.Join(expiredDomains, ", "),
			Context:  "Expired Certificates",
			LocalID:  gen.NextID(),
		})
	}

	dbg.Printf("%s success stage=demo_parsed results=%d", constants.FuncGetVTApiDomain, len(exec.Results))
}

func (m *module) processIPDemo(_ context.Context, target string, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	if !m.demoIPFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetVTApiIP, target)
		return
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncGetVTApiIP)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for VirusTotal (API key not configured)",
		LocalID:  gen.NextID(),
	})

	dataBytes, err := os.ReadFile("modules/virustotal/testdata/ip_page1.json")
	if err != nil {
		modutil.SetError(exec, "read fixture err: %v", err)
		return
	}
	modutil.SetRawFromBytes(exec, dataBytes)

	var data map[string]any
	if err := json.Unmarshal(dataBytes, &data); err != nil {
		modutil.SetError(exec, "unmarshal fixture err: %v", err)
		return
	}

	if dataMap, ok := data["data"].(map[string]any); ok {
		if attr, ok := dataMap["attributes"].(map[string]any); ok {
			m.extractIPMetadata(attr, target, exec, gen)
		}
	}

	for _, i := range []int{1, 2} {
		fixture := fmt.Sprintf("resolutions_page%d.json", i)
		fixturePath := filepath.Join("modules", "virustotal", "testdata", filepath.Clean(fixture))
		resDataBytes, err := os.ReadFile(filepath.Clean(fixturePath))
		if err != nil {
			continue
		}
		exec.RawData += "\n---\n" + string(resDataBytes)

		var resData map[string]any
		if err := json.Unmarshal(resDataBytes, &resData); err != nil {
			continue
		}

		items, ok := resData["data"].([]any)
		if !ok {
			continue
		}

		for _, item := range items {
			itemMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			m.extractIPResolution(itemMap, target, exec, gen)
		}
	}

	dbg.Printf("%s success stage=demo_parsed results=%d", constants.FuncGetVTApiIP, len(exec.Results))
}
