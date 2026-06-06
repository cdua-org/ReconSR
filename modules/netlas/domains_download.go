package netlas

import (
	"bytes"
	"encoding/json"
	"net/url"

	"cdua-org/ReconSR/internal/validator"
	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/orgdomain"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

type netlasCountResponse struct {
	Count int `json:"count"`
}

type downloadItem struct {
	Data struct {
		Domain string `json:"domain"`
		netlasDNS
	} `json:"data"`
}

func (m *netlasModule) getNetlasDomainsByQuery(target schema.Entity, fn string, gen *modutil.LocalIDGenerator) schema.ModuleExecution {
	exec := modutil.NewExecution(fn)
	targetValue := target.Value
	dbg.Printf("%s target=%q", fn, targetValue)

	if m.apiKey == demoIndicator {
		return m.runDemoDownloadByQuery(exec, target, fn, gen)
	}

	var query string
	switch fn {
	case constants.FuncGetNetlasDomainsByIP:
		query = "a:" + targetValue
	case constants.FuncGetNetlasDomainsByDomain:
		query = "domain:*." + targetValue
	default:
		return exec
	}

	countResp, ok := m.fetchDomainCount(&exec, query, targetValue, gen)
	if !ok {
		return exec
	}

	emitTargetApplied(&exec, target, targetValue, gen)

	if countResp.Count == 0 {
		dbg.Printf("%s no_results target=%q", fn, targetValue)
		return exec
	}

	size := m.resolveDownloadSize(countResp.Count)
	dbg.Printf("%s target=%q count=%d configured_limit=%d final_size=%d",
		fn, targetValue, countResp.Count, resolver.NetlasLimitPerOneDownload, size)

	payloadBytes, err := json.Marshal(buildDownloadPayload(query, size))
	if err != nil {
		modutil.SetError(&exec, "marshal payload: %v", err)
		return exec
	}

	items, ok := m.downloadAndParse(&exec, payloadBytes, targetValue, gen)
	if !ok {
		return exec
	}

	targetRef := &schema.EntityRef{Type: target.Type, Value: target.Value}
	emitDomainResults(&exec, items, targetRef, gen)

	dbg.Printf("%s success target=%q fetched=%d results=%d", fn, targetValue, len(items), len(exec.Results))
	return exec
}

func (m *netlasModule) fetchDomainCount(exec *schema.ModuleExecution, query, targetValue string, gen *modutil.LocalIDGenerator) (netlasCountResponse, bool) {
	countURL := netlasAPIBaseURL + "/domains_count/?q=" + url.QueryEscape(query)
	countBody, ok := m.doAPIRequest(exec, countURL, targetValue, gen)
	if !ok {
		return netlasCountResponse{}, false
	}

	var resp netlasCountResponse
	if err := json.Unmarshal(countBody, &resp); err != nil {
		dbg.Printf("%s error stage=parse_count err=%v", exec.Function, err)
		modutil.SetError(exec, "parse count json: %v", err)
		return netlasCountResponse{}, false
	}
	return resp, true
}

func emitTargetApplied(exec *schema.ModuleExecution, target schema.Entity, targetValue string, gen *modutil.LocalIDGenerator) {
	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     target.Type,
		Category: constants.CategoryNode,
		Value:    targetValue,
		LocalID:  gen.NextID(),
		Applied:  true,
	})
}

func (m *netlasModule) resolveDownloadSize(count int) int {
	m.mu.Lock()
	planLimit := m.limitPerDl
	m.mu.Unlock()

	size := count
	if resolver.NetlasLimitPerOneDownload > 0 && size > resolver.NetlasLimitPerOneDownload {
		size = resolver.NetlasLimitPerOneDownload
	}
	if planLimit > 0 && size > planLimit {
		size = planLimit
	}
	return size
}

func buildDownloadPayload(query string, size int) map[string]any {
	return map[string]any{
		"q":           query,
		"fields":      []string{"domain", "a", "aaaa", "ns", "mx", "txt", "cname"},
		"size":        size,
		"source_type": "include",
	}
}

func (m *netlasModule) downloadAndParse(exec *schema.ModuleExecution, payloadBytes []byte, targetValue string, gen *modutil.LocalIDGenerator) ([]downloadItem, bool) {
	downloadURL := netlasAPIBaseURL + "/domains/download/"

	dlBody, ok := m.doAPIRequestPOST(exec, downloadURL, payloadBytes, targetValue, gen)
	if !ok {
		return nil, false
	}

	exec.RawData = string(dlBody)

	return parseDownloadBody(exec, dlBody)
}

func parseDownloadBody(exec *schema.ModuleExecution, dlBody []byte) ([]downloadItem, bool) {
	trimmedBody := bytes.TrimSpace(dlBody)
	if len(trimmedBody) > 0 && trimmedBody[0] == '[' {
		var items []downloadItem
		if err := json.Unmarshal(trimmedBody, &items); err != nil {
			dbg.Printf("%s error stage=parse_download_array err=%v", exec.Function, err)
			modutil.SetError(exec, "parse download array: %v", err)
			return nil, false
		}
		return items, true
	}

	var items []downloadItem
	for line := range bytes.SplitSeq(trimmedBody, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var item downloadItem
		if err := json.Unmarshal(line, &item); err != nil {
			dbg.Printf("%s warning stage=parse_ndjson_item err=%v", exec.Function, err)
			continue
		}
		items = append(items, item)
	}
	return items, true
}

func emitDomainResults(exec *schema.ModuleExecution, items []downloadItem, targetRef *schema.EntityRef, gen *modutil.LocalIDGenerator) {
	for i := range items {
		domainVal := items[i].Data.Domain
		if domainVal == "" {
			continue
		}

		res, err := validator.Validate(constants.TypeDomain, domainVal)
		if err != nil {
			continue
		}

		domainID := gen.NextID()
		domainRef := &schema.EntityRef{Type: res.Type, Value: res.Value, LocalID: domainID}

		outOfScope := false
		if targetRef.Type == constants.TypeDomain {
			outOfScope = orgdomain.IsOutOfScope(res.Value, targetRef.Value)
		}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:       res.Type,
			Category:   constants.CategoryNode,
			Value:      res.Value,
			Tags:       []string{constants.TagPDNS},
			Source:     targetRef,
			LocalID:    domainID,
			Applied:    true,
			OutOfScope: outOfScope,
		})

		parseDomainDNS(exec, &items[i].Data.netlasDNS, domainRef, res.Value, gen)
	}
}
