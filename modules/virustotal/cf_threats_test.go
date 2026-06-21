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
			strings.Contains(r.Value, "Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe, Proto: TCP, Dst: 192.0.2.100:443")
	})

	requireResult(t, exec.Results, "IDS alert", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeIDSAlert &&
			strings.Contains(r.Value, "ET TROJAN Fake Malware C2 Checkin") &&
			strings.Contains(r.Value, "high")
	})

	requireResult(t, exec.Results, "tlsh hash", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileHash &&
			strings.HasPrefix(r.Value, "tlsh:")
	})

	assertAdvancedSecondHalf(t, &exec)
}

func assertAdvancedSecondHalf(t *testing.T, exec *schema.ModuleExecution) {
	requireResult(t, exec.Results, "yara rule", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeYaraRule && strings.Contains(r.Value, "android_banker_fake")
	})

	requireResult(t, exec.Results, "IDS match context", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeMatchContext &&
			strings.Contains(r.Value, "192.168.1.100") &&
			strings.Contains(r.Value, "c2.malware.local")
	})

	requireResult(t, exec.Results, "IDS stats", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileAnalyzer && strings.Contains(r.Value, "IDS Stats") && strings.Contains(r.Value, "High: 5") && strings.Contains(r.Value, "Medium: 2")
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
					"rule_level": "critical",
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

func buildIDSTestEntry(msg, severity, source string, alertContext any, invalid bool) any {
	if invalid {
		return "invalid_type_entry"
	}

	m := map[string]any{
		vtKeyRuleMsg: msg,
	}
	if severity != "" {
		m["alert_severity"] = severity
	}
	if source != "" {
		m["rule_source"] = source
	}
	if alertContext != nil {
		m["alert_context"] = alertContext
	}
	return m
}

func TestCommunicatingFiles_IDSEdgeCases(t *testing.T) {
	tests := []struct {
		alertContext any
		validate     func(_ *testing.T, _ *schema.ModuleExecution)
		name         string
		msg          string
		severity     string
		source       string
		invalid      bool
	}{
		{
			name:     "empty message",
			severity: "high",
			validate: func(t *testing.T, exec *schema.ModuleExecution) {
				for _, r := range exec.Results {
					if r.Type == constants.TypeIDSAlert && r.Value == "" {
						t.Fatalf("expected no IDS results for empty msg, got %+v", r)
					}
				}
			},
		},
		{
			name:   "without severity",
			msg:    "Test rule without severity",
			source: "Some Valid Source",
			validate: func(t *testing.T, exec *schema.ModuleExecution) {
				found := false
				for _, r := range exec.Results {
					if r.Type == constants.TypeIDSAlert && r.Value == "Test rule without severity" {
						found = true
						break
					}
				}
				if !found {
					t.Fatal("expected to find IDS alert without severity")
				}
			},
		},
		{
			name:     "empty severity",
			msg:      "Test rule with empty severity",
			severity: "",
			source:   "",
			validate: func(_ *testing.T, _ *schema.ModuleExecution) {},
		},
		{
			name: "invalid context element",
			msg:  "Test rule with invalid context element",
			alertContext: []any{
				"invalid_context_type",
			},
			validate: func(_ *testing.T, _ *schema.ModuleExecution) {},
		},
		{
			name:         "invalid alert_context type",
			msg:          "Test rule with invalid alert_context type",
			alertContext: "should_be_slice",
			validate:     func(_ *testing.T, _ *schema.ModuleExecution) {},
		},
		{
			name: "invalid IPs and valid domain",
			msg:  "Test rule with invalid IPs and valid domain",
			alertContext: []any{
				map[string]any{
					"dest_ip":              "not-an-ip",
					"src_ip":               "also-not-an-ip",
					constants.TypeHostname: "valid.example.com",
				},
			},
			validate: func(_ *testing.T, _ *schema.ModuleExecution) {},
		},
		{
			name: "protocol without ports",
			msg:  "Test rule protocol no ports",
			alertContext: []any{
				map[string]any{
					"protocol": "UDP",
				},
			},
			validate: func(t *testing.T, exec *schema.ModuleExecution) {
				foundProtocol := false
				for _, r := range exec.Results {
					if r.Type == constants.TypeMatchContext && strings.Contains(r.Value, "Proto: UDP") {
						foundProtocol = true
					}
				}
				if !foundProtocol {
					t.Fatal("expected TypeMatchContext with Proto: UDP")
				}
			},
		},
		{
			name: "port without IP and empty hostname",
			msg:  "Test rule port no ip",
			alertContext: []any{
				map[string]any{
					constants.TypeHostname: "    ",
					"dest_port":            float64(80),
					"src_port":             float64(443),
				},
			},
			validate: func(_ *testing.T, _ *schema.ModuleExecution) {},
		},
		{
			name:     "invalid_type_entry",
			invalid:  true,
			validate: func(_ *testing.T, _ *schema.ModuleExecution) {},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := modutil.NewLocalIDGenerator()
			exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

			entry := buildIDSTestEntry(tt.msg, tt.severity, tt.source, tt.alertContext, tt.invalid)

			extractCommunicatingFile(map[string]any{
				"id": "aabb2222ccdd3333eeff4444aabb5555ccdd6666eeff777788889999aabb0000",
				constants.KeyAttributes: map[string]any{
					vtKeyIDSResults: []any{
						entry,
					},
				},
			}, exec, gen)

			tt.validate(t, exec)
		})
	}
}

func TestCommunicatingFiles_IDSContextCoverage(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	entry := buildIDSTestEntry("Coverage test", "", "", []any{
		map[string]any{
			"EventID":     "42",
			"CommandLine": "cmd.exe /c ping 8.8.8.8",
			"url":         "http://example.com",
		},
	}, false)

	extractCommunicatingFile(map[string]any{
		"id": "cov0000000000000000000000000000000000000000000000000000000000000",
		constants.KeyAttributes: map[string]any{
			vtKeyIDSResults: []any{
				entry,
			},
		},
	}, exec, gen)

	found := false
	for _, r := range exec.Results {
		if r.Type == constants.TypeMatchContext && strings.Contains(r.Value, "Event: 42") && strings.Contains(r.Value, "Cmd: cmd.exe /c ping 8.8.8.8") && strings.Contains(r.Value, "URL: http://example.com") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected full network context to be parsed")
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
