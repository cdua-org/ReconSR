package shodan

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestAppendShodanTagResults(t *testing.T) {
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}

	appendShodanTagResults(&exec, []string{" faketag ", "risky", "faketag", "", "   "})

	requireTagPropertyResults(t, exec.Results, "faketag", "risky")
}

func TestAppendShodanTagResultsEmptyInput(t *testing.T) {
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}

	appendShodanTagResults(&exec, nil)
	appendShodanTagResults(&exec, []string{"", "   "})

	if len(exec.Results) != 0 {
		t.Fatalf("expected no tag results for empty input, got %+v", exec.Results)
	}
}
