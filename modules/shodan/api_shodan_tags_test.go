package shodan

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestAppendShodanTagResults(t *testing.T) {
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIIP}

	gen := modutil.NewLocalIDGenerator()
	appendShodanTagResults(&exec, []string{" faketag ", "risky", "faketag", "", "   "}, gen)

	requireTagPropertyResults(t, exec.Results, "faketag", "risky")
}

func TestAppendShodanTagResultsEmptyInput(t *testing.T) {
	exec := schema.ModuleExecution{Function: constants.FuncGetShodanAPIDomain}
	gen := modutil.NewLocalIDGenerator()

	appendShodanTagResults(&exec, nil, gen)
	appendShodanTagResults(&exec, []string{"", "   "}, gen)

	if len(exec.Results) != 0 {
		t.Fatalf("expected no tag results for empty input, got %+v", exec.Results)
	}
}
