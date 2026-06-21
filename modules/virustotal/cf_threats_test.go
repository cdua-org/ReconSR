package virustotal

import (
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

func TestCommunicatingFiles_Advanced(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/domains/advanced.example.com/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "advanced.example.com",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	requireResult(t, exec.Results, "sigma rule", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeSigmaRule &&
			strings.Contains(r.Value, "Suspicious Powershell Download") &&
			strings.Contains(r.Value, "high")
	})

	requireResult(t, exec.Results, "sigma rule match context", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeMatchContext &&
			strings.Contains(r.Value, "Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe, Protocol: tcp, DestinationIp: 192.0.2.100, DestinationPort: 443")
	})

	requireResult(t, exec.Results, "IDS alert", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeIDSAlert &&
			strings.Contains(r.Value, "ET TROJAN Fake Malware C2 Checkin") &&
			strings.Contains(r.Value, "high")
	})

	requireResult(t, exec.Results, "malware config with family", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeMalwareConfig &&
			strings.Contains(r.Value, "FakeBot") &&
			strings.Contains(r.Value, "192.0.2.1")
	})

	requireResult(t, exec.Results, "threat classification label", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeThreatType &&
			r.Value == "trojan.fakebot/dropper"
	})

	requireResult(t, exec.Results, "dropper category", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeCategory &&
			r.Value == "dropper"
	})

	requireResult(t, exec.Results, "tlsh hash", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileHash &&
			strings.HasPrefix(r.Value, "tlsh:")
	})
}

func TestCommunicatingFiles_SuspiciousOnly(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "bbbb1111cccc2222dddd3333eeee4444ffff5555aaaa666677778888aaaa9999",
		constants.KeyAttributes: map[string]any{
			vtKeyAnalysisStats: map[string]any{
				constants.TagMalicious:  float64(0),
				constants.TagSuspicious: float64(3),
			},
		},
	}, exec, gen)

	found := false
	for _, r := range exec.Results {
		if r.Type == constants.TypeFileHash && len(r.Tags) > 0 && r.Tags[0] == constants.TagSuspicious {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected suspicious tag on hash when only suspicious > 0")
	}
}

func TestCommunicatingFiles_CleanFile(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "cccc1111dddd2222eeee3333ffff4444aaaa5555bbbb666677778888cccc9999",
		constants.KeyAttributes: map[string]any{
			vtKeyAnalysisStats: map[string]any{
				constants.TagMalicious:  float64(0),
				constants.TagSuspicious: float64(0),
			},
		},
	}, exec, gen)

	for _, r := range exec.Results {
		if r.Type == constants.TypeThreatScore {
			t.Fatal("expected no threat score for clean file")
		}
	}
}

func TestCommunicatingFiles_SandboxVerdicts(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "dddd1111eeee2222ffff3333aaaa4444bbbb5555cccc666677778888dddd9999",
		constants.KeyAttributes: map[string]any{
			vtKeySandboxVerdict: map[string]any{
				"TestSandbox": map[string]any{
					constants.KeyCategory: constants.TagMalicious,
					"sandbox_name":        "TestSandbox",
					"malware_names": []any{
						"FakeMiner",
					},
				},
				"CleanSandbox": map[string]any{
					constants.KeyCategory: "",
					"sandbox_name":        "CleanSandbox",
				},
			},
		},
	}, exec, gen)

	found := false
	for _, r := range exec.Results {
		if r.Type == constants.TypeSandboxVerdict && strings.Contains(r.Value, "TestSandbox") {
			if !strings.Contains(r.Value, constants.TagMalicious) || !strings.Contains(r.Value, "FakeMiner") {
				t.Fatalf("sandbox verdict missing expected content: %+v", r)
			}
			found = true
		}
		if r.Type == constants.TypeSandboxVerdict && strings.Contains(r.Value, "CleanSandbox") {
			t.Fatal("harmless sandbox should be filtered out")
		}
	}
	if !found {
		t.Fatal("expected malicious sandbox verdict result")
	}
}

func TestCommunicatingFiles_SandboxUndetected(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "eeee1111ffff2222aaaa3333bbbb4444cccc5555dddd666677778888eeee9999",
		constants.KeyAttributes: map[string]any{
			vtKeySandboxVerdict: map[string]any{
				"UndetectedSandbox": map[string]any{
					constants.KeyCategory: "undetected",
				},
			},
		},
	}, exec, gen)

	for _, r := range exec.Results {
		if r.Type == constants.TypeSandboxVerdict && strings.Contains(r.Value, "Sandbox") {
			t.Fatal("undetected sandbox should not produce sandbox_verdict results")
		}
	}
}

func TestCommunicatingFiles_YaraEmptyRuleName(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "ffff1111aaaa2222bbbb3333cccc4444dddd5555eeee666677778888ffff9999",
		constants.KeyAttributes: map[string]any{
			"crowdsourced_yara_results": []any{
				map[string]any{
					"rule_name": "",
					"source":    "fake-source",
				},
				map[string]any{
					"source": "no-rule-name",
				},
			},
		},
	}, exec, gen)

	for _, r := range exec.Results {
		if r.Type == constants.TypeYaraRule {
			t.Fatal("expected no yara results for empty rule_name")
		}
	}
}

func TestCommunicatingFiles_SigmaEmptyTitle(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "aabb1111ccdd2222eeff3333aabb4444ccdd5555eeff666677778888aabb9999",
		constants.KeyAttributes: map[string]any{
			"sigma_analysis_results": []any{
				map[string]any{
					"rule_title": "",
					"rule_level": "high",
				},
			},
		},
	}, exec, gen)

	for _, r := range exec.Results {
		if r.Type == constants.TypeSigmaRule {
			t.Fatal("expected no sigma results for empty rule_title")
		}
	}
}

func TestCommunicatingFiles_IDSEdgeCases(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "aabb2222ccdd3333eeff4444aabb5555ccdd6666eeff777788889999aabb0000",
		constants.KeyAttributes: map[string]any{
			"crowdsourced_ids_results": []any{
				map[string]any{
					vtKeyRuleMsg:     "",
					"alert_severity": "high",
				},
				map[string]any{
					vtKeyRuleMsg:  "Test rule without severity",
					"rule_source": "Some Valid Source",
				},
				map[string]any{
					vtKeyRuleMsg:     "Test rule with empty severity",
					"alert_severity": "",
					"rule_source":    "",
				},
				"invalid_type_entry",
			},
		},
	}, exec, gen)

	foundWithoutSeverity := false
	for _, r := range exec.Results {
		if r.Type == constants.TypeIDSAlert {
			if r.Value == "" {
				t.Fatalf("expected no IDS results for empty msg, got %+v", r)
			}
			if r.Value == "Test rule without severity" {
				foundWithoutSeverity = true
			}
		}
	}
	if !foundWithoutSeverity {
		t.Fatal("expected to find IDS alert without severity")
	}
}

func TestCommunicatingFiles_MalwareConfigEmpty(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "bbcc1111ddee2222ffaa3333bbcc4444ddee5555ffaa666677778888bbcc9999",
		constants.KeyAttributes: map[string]any{
			"malware_config": map[string]any{},
		},
	}, exec, gen)

	for _, r := range exec.Results {
		if r.Type == constants.TypeMalwareConfig {
			t.Fatal("expected no malware config for empty config object")
		}
	}
}

func TestCommunicatingFiles_SandboxEmptyCategory(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "ffaa1111bbcc2222ddee3333ffaa4444bbcc5555ddee666677778888ffaa9999",
		constants.KeyAttributes: map[string]any{
			vtKeySandboxVerdict: map[string]any{
				"EmptyCat": map[string]any{
					constants.KeyCategory: "",
				},
			},
		},
	}, exec, gen)

	for _, r := range exec.Results {
		if r.Type == constants.TypeSandboxVerdict && strings.Contains(r.Value, "Sandbox") {
			t.Fatal("empty category should be ignored")
		}
	}
}

func TestCommunicatingFiles_ReputationFormatting(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		name     string
		expected string
		rep      float64
	}{
		{"malicious", "-15 (Malicious)", -15},
		{"suspicious", "-2 (Suspicious)", -2},
		{"positive", "+25 (Safe/Benign)", 25},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}
			extractCommunicatingFile(map[string]any{
				"id": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcde3",
				constants.KeyAttributes: map[string]any{
					vtKeyReputation: tt.rep,
				},
			}, exec, gen)

			found := false
			for _, r := range exec.Results {
				if r.Type == constants.TypeReputation && r.Value == tt.expected && r.Context == "Community Reputation" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected to extract reputation '%s'", tt.expected)
			}
		})
	}
}

func TestGetSigmaMatchContextSortFunc(t *testing.T) {
	keys := []string{"CommandLine", "DestinationIp", "Key1", "Key2"}
	less := getSigmaMatchContextSortFunc(keys)

	if !less(0, 1) {
		t.Errorf("expected CommandLine < DestinationIp")
	}
	if less(1, 0) {
		t.Errorf("expected CommandLine < DestinationIp")
	}

	if !less(0, 2) {
		t.Errorf("expected CommandLine < Key1")
	}
	if less(2, 0) {
		t.Errorf("expected CommandLine < Key1")
	}

	if !less(2, 3) {
		t.Errorf("expected Key1 < Key2")
	}
	if less(3, 2) {
		t.Errorf("expected Key1 < Key2")
	}
}
