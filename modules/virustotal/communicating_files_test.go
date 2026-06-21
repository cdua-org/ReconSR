package virustotal

import (
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func execVTCommFiles(t *testing.T, mod *module, funcName string, target schema.Entity) schema.ModuleExecution {
	t.Helper()

	output, err := mod.Exec(schema.ModuleInput{
		Target:    target,
		Functions: []string{funcName},
	})
	if err != nil {
		t.Fatalf("Exec returned error: %v", err)
	}
	if len(output.Executions) != 1 {
		t.Fatalf("expected 1 execution, got %d", len(output.Executions))
	}

	return output.Executions[0]
}

func setupCommFilesTest(t *testing.T, path, fixture string) *module {
	t.Helper()

	originalDelay := resolver.VirustotalDelayMs
	resolver.VirustotalDelayMs = 0
	t.Cleanup(func() { resolver.VirustotalDelayMs = originalDelay })

	responses := map[string]string{path: fixture}
	_, server := newVTMockServer(t, responses, nil)
	t.Cleanup(server.Close)
	setVTBaseURL(t, server.URL+"/api/v3")

	return &module{apiKey: fixtureTestAPIKey}
}

func TestCommunicatingFiles_IPWinPE(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/ip_addresses/192.0.2.1/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiIPCommunicatingFiles, schema.Entity{
		Type:  constants.TypeIPv4,
		Value: "192.0.2.1",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	requireResult(t, exec.Results, "primary sha256 hash node", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileHash &&
			r.Category == constants.CategoryProperty &&
			strings.HasPrefix(r.Value, "sha256:")
	})

	requireResult(t, exec.Results, "file name", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileName &&
			r.Value == "blablabla.exe"
	})

	requireResult(t, exec.Results, "IDS match context", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeMatchContext &&
			strings.Contains(r.Value, "192.168.1.100") &&
			strings.Contains(r.Value, "c2.malware.local")
	})
}

func TestCommunicatingFiles_EmptyResponse(t *testing.T) {
	emptyResponse := `{"data": [], "meta": {"count": 0}}`
	mod := setupCommFilesTest(t, "/api/v3/domains/empty.example.com/communicating_files?limit=40", emptyResponse)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "empty.example.com",
	})

	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}
	if len(exec.Results) != 0 {
		t.Fatalf("expected 0 results for empty response, got %d", len(exec.Results))
	}
}

func TestCommunicatingFiles_MissingID(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		constants.KeyAttributes: map[string]any{
			"sha256": "abc123",
		},
	}, exec, gen)

	if len(exec.Results) != 0 {
		t.Fatalf("expected 0 results when id is missing, got %d", len(exec.Results))
	}
}

func TestCommunicatingFiles_MissingAttributes(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
	}, exec, gen)

	if len(exec.Results) != 0 {
		t.Fatalf("expected 0 results when attributes missing, got %d", len(exec.Results))
	}
}

func TestCommunicatingFiles_EmptyID(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id":                    "",
		constants.KeyAttributes: map[string]any{},
	}, exec, gen)

	if len(exec.Results) != 0 {
		t.Fatalf("expected 0 results when id is empty, got %d", len(exec.Results))
	}
}

func TestCommunicatingFiles_MinimalFile(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666777788889999aaaa",
		constants.KeyAttributes: map[string]any{
			"sha256": "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666777788889999aaaa",
		},
	}, exec, gen)

	if len(exec.Results) != 1 {
		t.Fatalf("expected 1 result for minimal file (just sha256), got %d", len(exec.Results))
	}

	r := exec.Results[0]
	if r.Type != constants.TypeFileHash {
		t.Fatalf("expected type %s, got %s", constants.TypeFileHash, r.Type)
	}
	if r.Category != constants.CategoryProperty {
		t.Fatalf("expected category %s, got %s", constants.CategoryProperty, r.Category)
	}
	if !strings.HasPrefix(r.Value, "sha256:") {
		t.Fatalf("expected sha256 prefix, got %s", r.Value)
	}
}

func TestCommunicatingFiles_SourceChaining(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "ddee1111ffaa2222bbcc3333ddee4444ffaa5555bbcc666677778888ddee9999",
		constants.KeyAttributes: map[string]any{
			constants.KeyMD5:   "aabbccdd11223344aabbccdd11223344",
			"meaningful_name":  "test-chain.exe",
			"type_description": "Win32 EXE",
			"size":             float64(1024),
		},
	}, exec, gen)

	var primaryLocalID int
	for _, r := range exec.Results {
		if r.Type == constants.TypeFileHash && r.Category == constants.CategoryProperty {
			primaryLocalID = r.LocalID
			break
		}
	}

	if primaryLocalID == 0 {
		t.Fatal("primary sha256 node not found")
	}

	for _, r := range exec.Results {
		if r.Category == constants.CategoryProperty && r.Source != nil {
			if r.Source.LocalID != primaryLocalID {
				t.Fatalf("property %s:%s has Source.LocalID=%d, expected %d", r.Type, r.Value, r.Source.LocalID, primaryLocalID)
			}
			if r.Source.Type != constants.TypeFileHash {
				t.Fatalf("property %s has Source.Type=%s, expected %s", r.Type, r.Source.Type, constants.TypeFileHash)
			}
		}
	}
}

func TestCommunicatingFiles_Capabilities(t *testing.T) {
	mod := &module{apiKey: fixtureTestAPIKey}
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities error: %v", err)
	}

	domainFilesCaps, ok := caps.CustomFunctions[constants.FuncGetVTApiDomainCommunicatingFiles]
	if !ok {
		t.Fatalf("expected %s in custom functions", constants.FuncGetVTApiDomainCommunicatingFiles)
	}
	if len(domainFilesCaps.InputTypes) == 0 {
		t.Fatal("expected input types for domain files")
	}

	ipFilesCaps, ok := caps.CustomFunctions[constants.FuncGetVTApiIPCommunicatingFiles]
	if !ok {
		t.Fatalf("expected %s in custom functions", constants.FuncGetVTApiIPCommunicatingFiles)
	}
	if len(ipFilesCaps.InputTypes) == 0 {
		t.Fatal("expected input types for IP files")
	}
}

func ctxVal(v any) map[string]any {
	return map[string]any{"values": v}
}

func buildSigmaResults(rules []struct {
	Ctx   any
	Title string
}) []any {
	res := make([]any, 0, 1+len(rules))
	res = append(res, true)
	for _, r := range rules {
		m := map[string]any{"rule_title": r.Title}
		if r.Ctx != nil {
			m["match_context"] = r.Ctx
		}
		res = append(res, m)
	}
	return res
}

func TestCommunicatingFiles_InvalidAndEdgeCases(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "eeff1111aabb2222ccdd3333eeff4444aabb5555ccdd666677778888eeff9999",
		constants.KeyAttributes: map[string]any{
			"crowdsourced_yara_results": []any{
				42,
				"not_a_map_str",
			},
			"sigma_analysis_results": buildSigmaResults([]struct {
				Ctx   any
				Title string
			}{
				{Title: ""},
				{
					Title: "Rule 1",
					Ctx: []any{
						42,
						map[string]any{"not_values": "test"},
						ctxVal("not_valid_map"),
						ctxVal(map[string]any{
							"Key1":            "Val1",
							"Key2":            42,
							"Key3":            nil,
							"Key4":            "",
							"SourceIp":        "10.0.0.1",
							"DestinationPort": 80,
						}),
						ctxVal(map[string]any{}),
					},
				},
				{Title: "Rule 2 (missing match_context)"},
				{Title: "Rule 3 (empty match_context)", Ctx: []any{}},
			}),
			vtKeyIDSResults: []any{
				nil,
			},
			vtKeySandboxVerdict: map[string]any{
				"bad_entry": "not_valid_map_entry",
			},
			"signature_info": map[string]any{
				"x509": "not_valid_list",
			},
		},
	}, exec, gen)

	requireResult(t, exec.Results, "sigma rule match context edge cases", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeMatchContext &&
			strings.Contains(r.Value, "Src: 10.0.0.1, DstPort: 80, Key1: Val1, Key2: 42")
	})

	for _, r := range exec.Results {
		switch r.Type {
		case constants.TypeYaraRule, constants.TypeIDSAlert:
			t.Fatalf("unexpected result for invalid type input: %+v", r)
		}
	}
}
