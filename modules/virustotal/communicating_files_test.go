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

func TestCommunicatingFiles_DomainWinPE_Hashes(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/domains/winpe.example.com/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "winpe.example.com",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}
	if len(exec.Results) == 0 {
		t.Fatal("expected results, got 0")
	}

	requireResult(t, exec.Results, "primary sha256 hash node", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileHash &&
			r.Category == constants.CategoryProperty &&
			strings.HasPrefix(r.Value, "sha256:")
	})

	for _, prefix := range []string{"md5:", "sha1:", "imphash:", "ssdeep:", "vhash:", "authentihash:"} {
		requireResult(t, exec.Results, prefix+" hash property", func(r schema.ModuleResult) bool {
			return r.Type == constants.TypeFileHash &&
				r.Category == constants.CategoryProperty &&
				strings.HasPrefix(r.Value, prefix)
		})
	}

	for _, r := range exec.Results {
		if r.LocalID == 0 {
			t.Fatalf("result with LocalID 0 found: %+v", r)
		}
	}
}

func TestCommunicatingFiles_DomainWinPE_Metadata(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/domains/meta.example.com/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "meta.example.com",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	requireResult(t, exec.Results, "file name", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileName &&
			r.Value == "blablabla.exe"
	})

	requireResult(t, exec.Results, "file info with type and size", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileInfo &&
			strings.Contains(r.Value, "Win32 EXE") &&
			strings.Contains(r.Value, "445440")
	})

	requireResult(t, exec.Results, "threat score", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeThreatScore &&
			strings.Contains(r.Value, "Malicious: 4")
	})

	requireResult(t, exec.Results, "malicious tag on hash", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileHash &&
			len(r.Tags) > 0 && r.Tags[0] == constants.TagMalicious
	})

	requireResult(t, exec.Results, "creation date", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeDate &&
			strings.HasPrefix(r.Value, "Creation Date:")
	})

	requireResult(t, exec.Results, "peexe tag", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeTag && r.Value == "peexe"
	})
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
}

func TestCommunicatingFiles_APK(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/domains/apk.example.com/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "apk.example.com",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	requireResult(t, exec.Results, "primary sha256 hash node (APK)", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileHash &&
			r.Category == constants.CategoryProperty &&
			strings.HasPrefix(r.Value, "sha256:e3b0c44298fc1c14")
	})

	requireResult(t, exec.Results, "yara rule", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeYaraRule &&
			strings.Contains(r.Value, "android_banker_fake") &&
			strings.Contains(r.Value, "John Doe")
	})

	requireResult(t, exec.Results, "threat category banker", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeCategory &&
			r.Value == "banker"
	})

	requireResult(t, exec.Results, "threat category trojan", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeCategory &&
			r.Value == "trojan"
	})

	requireResult(t, exec.Results, "file name (APK)", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileName &&
			r.Value == "fake_bank.apk"
	})

	requireResult(t, exec.Results, "file info with Android type", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileInfo &&
			strings.Contains(r.Value, "Android")
	})
}

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

func TestCommunicatingFiles_FileMagic(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "ccdd1111eeff2222aabb3333ccdd4444eeff5555aabb666677778888ccdd9999",
		constants.KeyAttributes: map[string]any{
			"magic": "ELF 64-bit LSB executable",
		},
	}, exec, gen)

	found := false
	for _, r := range exec.Results {
		if r.Type == constants.TypeFileMagic && strings.Contains(r.Value, "ELF 64-bit") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected file magic property")
	}
}

func TestCommunicatingFiles_URLDecodeAndDates(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd",
		constants.KeyAttributes: map[string]any{
			"meaningful_name":       "%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%80%20%D1%84%D0%B0%D0%B9%D0%BB%D0%B0.pdf",
			"names":                 []any{"%E7%A4%BA%E4%BE%8B%E6%96%87%E4%BB%B6.xls", "%D9%85%D9%84%D9%81%20%D9%85%D8%AB%D8%A7%D9%84.txt", "top_secret_%F0%9F%94%A5_!%40%23.bin", "example%20file%20%F0%9F%93%8E.doc"},
			"first_submission_date": float64(1587494940),
			"last_submission_date":  float64(1666615740),
			"pdf_info": map[string]any{
				"header":     "%PDF-1.6",
				"javascript": float64(1),
				"acroform":   float64(2),
			},
		},
	}, exec, gen)

	requireResult(t, exec.Results, "URL decoded meaningful name", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileName && r.Value == "пример файла.pdf"
	})

	requireResult(t, exec.Results, "first submission date", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeDate && r.Value == "First Submission: 2020-04-21 18:49:00"
	})

	requireResult(t, exec.Results, "last submission date", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeDate && r.Value == "Last Submission: 2022-10-24 12:49:00"
	})

	requireResult(t, exec.Results, "pdf info", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileMeta && strings.Contains(r.Value, "PDF Info") && strings.Contains(r.Value, "JavaScript: 1") && strings.Contains(r.Value, "AcroForm: 2") && strings.Contains(r.Value, "Header: %PDF-1.6")
	})
}

func TestCommunicatingFiles_AnalyzerStatsAndMultipleNames(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
		constants.KeyAttributes: map[string]any{
			"names":           []any{"%E6%B5%8B%E8%AF%95%E6%96%87%E4%BB%B6.xls", "payload_v2.exe", "config_data.bin"},
			"times_submitted": float64(42),
			"unique_sources":  float64(12),
			"total_votes": map[string]any{
				"harmless":  float64(5),
				"malicious": float64(15),
			},
		},
	}, exec, gen)

	requireResult(t, exec.Results, "URL decoded from names[0]", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileName && r.Value == "测试文件.xls"
	})
	requireResult(t, exec.Results, "secondary name", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileName && r.Value == "payload_v2.exe"
	})
	requireResult(t, exec.Results, "backup name", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileName && r.Value == "config_data.bin"
	})
	requireResult(t, exec.Results, "analyzer info", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileAnalyzer &&
			strings.Contains(r.Value, "Times Submitted: 42") &&
			strings.Contains(r.Value, "Unique Sources: 12") &&
			strings.Contains(r.Value, "Community Votes: Harmless: 5, Malicious: 15")
	})
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
			"crowdsourced_ids_results": []any{
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
			strings.Contains(r.Value, "SourceIp: 10.0.0.1, DestinationPort: 80, Key1: Val1, Key2: 42, Key3: <nil>")
	})

	for _, r := range exec.Results {
		switch r.Type {
		case constants.TypeYaraRule, constants.TypeIDSAlert:
			t.Fatalf("unexpected result for invalid type input: %+v", r)
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

func TestCommunicatingFiles_APK_EdgeCases(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		tpVal      any
		dateVal    any
		id         string
		expectDate string
		isMap      bool
		hasDate    bool
		expectCert bool
	}{
		{id: "1111111111111111111111111111111111111111111111111111111111111111", isMap: false},
		{id: "2222222222222222222222222222222222222222222222222222222222222222", isMap: true, tpVal: 12345},
		{id: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", isMap: true, tpVal: "da39a3ee5e6b4b0d3255bfef95601890afd80709", hasDate: true, dateVal: "Not a valid date string", expectDate: "Not a valid date string", expectCert: true},
	}

	for _, tt := range tests {
		var certVal any = 123
		if tt.isMap {
			m := make(map[string]any)
			m["thumbprint"] = tt.tpVal
			if tt.hasDate {
				m["validto"] = tt.dateVal
			}
			certVal = m
		}

		exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}
		extractCommunicatingFile(map[string]any{
			"id": tt.id,
			constants.KeyAttributes: map[string]any{
				"androguard": map[string]any{
					"certificate": certVal,
				},
			},
		}, exec, gen)

		foundFp := false
		foundDate := false
		for _, r := range exec.Results {
			if r.Type == constants.TypeCertFingerprint {
				foundFp = true
			}
			if r.Type == constants.TypeCertNotAfter {
				foundDate = true
				if r.Value != tt.expectDate {
					t.Fatalf("expected date %s, got %s", tt.expectDate, r.Value)
				}
			}
		}

		if tt.expectCert && !foundFp {
			t.Fatal("expected fingerprint but got none")
		}
		if !tt.expectCert && foundFp {
			t.Fatal("expected no fingerprint but got one")
		}
		if tt.expectDate != "" && !foundDate {
			t.Fatal("expected not after date but got none")
		}
	}
}

func TestCommunicatingFiles_X509_EdgeCases(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	tests := []struct {
		tpVal   any
		dateVal any
		isMap   bool
		hasTp   bool
		hasDate bool
	}{
		{isMap: false},
		{isMap: true, hasTp: false},
		{isMap: true, hasTp: true, tpVal: ""},
		{isMap: true, hasTp: true, tpVal: "aabbcc", hasDate: true, dateVal: "invalid-date"},
	}

	for _, tt := range tests {
		var item any = 123
		if tt.isMap {
			m := make(map[string]any)
			if tt.hasTp {
				m["thumbprint"] = tt.tpVal
			}
			if tt.hasDate {
				m["valid to"] = tt.dateVal
			}
			item = m
		}

		sigInfo := map[string]any{
			"x509": []any{item},
		}
		extractX509Certificates(exec, sigInfo, &schema.EntityRef{}, gen)
	}

	foundInvalidDateFallback := false
	for _, r := range exec.Results {
		if r.Type == constants.TypeCertNotAfter && r.Value == "invalid-date" {
			foundInvalidDateFallback = true
		}
	}

	if !foundInvalidDateFallback {
		t.Fatal("expected invalid date to fallback to string value")
	}
}

func TestCommunicatingFiles_APK_Analyzer(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/domains/apk.example.com/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "apk.example.com",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	requireResult(t, exec.Results, "apk analyzer output", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileAnalyzer &&
			strings.Contains(r.Value, "Dangerous Permissions: CAMERA")
	})

	requireResult(t, exec.Results, "apk meta output", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileMeta &&
			strings.Contains(r.Value, "com.example.malware (v1.0)") &&
			strings.Contains(r.Value, "com.example.malware.MainActivity") &&
			strings.Contains(r.Value, "Min SDK: 21") &&
			strings.Contains(r.Value, "Target SDK: 28")
	})

	requireResult(t, exec.Results, "apk cert issuer", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeCertIssuer && r.Value == "CN=FakeBank, O=Scam"
	})

	requireResult(t, exec.Results, "apk cert not after", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeCertNotAfter && strings.Contains(r.Value, "2030-01-01")
	})
}

func TestCommunicatingFiles_APK_StringPermissions(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()
	exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

	extractCommunicatingFile(map[string]any{
		"id": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		constants.KeyAttributes: map[string]any{
			"androguard": map[string]any{
				"permission_details": map[string]any{
					"android.permission.TEST_PERM": "Dangerous|Instant",
					"android.permission.IGNORE_ME": "normal",
				},
			},
		},
	}, exec, gen)

	found := false
	for _, r := range exec.Results {
		if r.Type == constants.TypeFileAnalyzer && strings.Contains(r.Value, "Dangerous Permissions: TEST_PERM") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected to extract dangerous string permissions")
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
				"id": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
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
