package virustotal

import (
	"context"
	"fmt"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func (m *module) processCommunicatingFiles(ctx context.Context, funcName, urlPath string, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	if m.apiKey == demoIndicator {
		m.processCommunicatingFilesDemo(ctx, funcName, exec, gen)
		return
	}
	reqURL := fmt.Sprintf("%s/%s?limit=40", baseURL, urlPath)
	dbg.Printf("%s phase=communicating_files url=%q", funcName, reqURL)

	m.processPaginated(ctx, reqURL, exec, gen, func(item map[string]any) {
		extractCommunicatingFile(item, exec, gen)
	})

	dbg.Printf("%s success results=%d", funcName, len(exec.Results))
}

func extractCommunicatingFile(item map[string]any, exec *schema.ModuleExecution, gen *modutil.LocalIDGenerator) {
	sha256, ok := item["id"].(string)
	if !ok || sha256 == "" {
		return
	}

	attr, ok := item[constants.KeyAttributes].(map[string]any)
	if !ok {
		return
	}

	hashRef := &schema.EntityRef{
		Type:  constants.TypeFileHash,
		Value: "sha256:" + sha256,
	}

	primaryID := gen.NextID()
	hashRef.LocalID = primaryID

	exec.Results = append(exec.Results, schema.ModuleResult{
		Type:     constants.TypeFileHash,
		Category: constants.CategoryProperty,
		Value:    "sha256:" + sha256,
		LocalID:  primaryID,
	})

	appendFileHashes(exec, attr, hashRef, gen)
	appendFileName(exec, attr, hashRef, gen)
	appendFileInfo(exec, attr, hashRef, gen)
	appendFileMagic(exec, attr, hashRef, gen)
	appendFileDates(exec, attr, hashRef, gen)
	appendFileThreatScore(exec, attr, hashRef, gen)
	appendFileThreatClassification(exec, attr, hashRef, gen)
	appendFileCategories(exec, attr, hashRef, gen)
	appendFileYaraRules(exec, attr, hashRef, gen)
	appendFileSigmaRules(exec, attr, hashRef, gen)
	appendFileIDSAlerts(exec, attr, hashRef, gen)
	appendFileMalwareConfig(exec, attr, hashRef, gen)
	appendFileTags(exec, attr, hashRef, gen)
	appendFileSandboxVerdicts(exec, attr, hashRef, gen)
	appendFileReputation(exec, attr, hashRef, gen)
	appendFileCertificates(exec, attr, hashRef, gen)
	appendFileDebInfo(exec, attr, hashRef, gen)
}
