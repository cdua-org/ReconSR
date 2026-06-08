package shodan

import (
	"strings"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func appendShodanTagResults(exec *schema.ModuleExecution, tags []string, gen *modutil.LocalIDGenerator) {
	if len(tags) == 0 {
		return
	}

	seen := make(map[string]struct{}, len(tags))
	for _, rawTag := range tags {
		tag := strings.TrimSpace(rawTag)
		if tag == "" {
			continue
		}
		if _, exists := seen[tag]; exists {
			continue
		}
		seen[tag] = struct{}{}

		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeTag,
			Category: constants.CategoryProperty,
			Value:    tag,
			LocalID:  gen.NextID(),
		})
	}
}
