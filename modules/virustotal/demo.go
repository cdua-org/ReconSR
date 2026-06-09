package virustotal

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

//go:embed testdata/domain_page1.json testdata/subdomains_page1.json testdata/subdomains_page2.json testdata/ip_page1.json testdata/resolutions_page1.json testdata/resolutions_page2.json
var demoData embed.FS

var readDemoFile = demoData.ReadFile

func (m *module) processDomainDemo(_ context.Context, targetType, target string, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	if !m.demoDomainFired.CompareAndSwap(false, true) {
		dbg.Printf("%s skipped stage=demo_already_fired target=%q", constants.FuncGetVTApiDomain, target)
		return
	}

	dbg.Printf("%s start stage=demo_mode", constants.FuncGetVTApiDomain)

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeInfo,
		Category: constants.CategoryProperty,
		Value:    "⚠️ DEMO MODE: Showing sample data for VirusTotal Domain (API key not configured)",
		LocalID:  gen.NextID(),
	})

	dataBytes, err := readDemoFile("testdata/domain_page1.json")
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
		if attr, ok := dataMap[keyAttributes].(map[string]any); ok {
			m.extractDomainMetadata(attr, targetType, target, exec, gen)
		}
	}

	disableCertExpired := false

	var expiredDomains []string

	for _, i := range []int{1, 2} {
		fixture := fmt.Sprintf("subdomains_page%d.json", i)
		fixturePath := "testdata/" + fixture
		subDataBytes, err := readDemoFile(fixturePath)
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
			if itemMap, itemOK := item.(map[string]any); itemOK {
				if expired := m.extractSubdomain(itemMap, targetType, target, disableCertExpired, exec, gen); expired != "" {
					expiredDomains = append(expiredDomains, expired)
				}
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
		Value:    "⚠️ DEMO MODE: Showing sample data for VirusTotal IP (API key not configured)",
		LocalID:  gen.NextID(),
	})

	dataBytes, err := readDemoFile("testdata/ip_page1.json")
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
		if attr, ok := dataMap[keyAttributes].(map[string]any); ok {
			m.extractIPMetadata(attr, target, exec, gen)
		}
	}

	for _, i := range []int{1, 2} {
		fixture := fmt.Sprintf("resolutions_page%d.json", i)
		fixturePath := "testdata/" + fixture
		resDataBytes, err := readDemoFile(fixturePath)
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
