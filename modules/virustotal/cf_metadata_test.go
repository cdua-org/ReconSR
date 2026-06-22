package virustotal

import (
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

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

func TestCommunicatingFiles_BundleInfo(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/domains/bundle.example.com/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "bundle.example.com",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	requireResult(t, exec.Results, "clean zip bundle info", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeBundleInfo &&
			strings.Contains(r.Value, "Bundle Type: ZIP") &&
			strings.Contains(r.Value, "Files: 2") &&
			strings.Contains(r.Value, "Uncompressed Size: 222702") &&
			strings.Contains(r.Value, "Extensions: exe (1)") &&
			strings.Contains(r.Value, "File Types: Portable Executable (1), XML (1)")
	})

	requireResult(t, exec.Results, "clean zip password", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypePassword &&
			r.Value == "infected" &&
			r.Context == "Bundle Info"
	})

	requireResult(t, exec.Results, "corrupt gzip bundle info", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeBundleInfo &&
			strings.Contains(r.Value, "Bundle Type: GZIP") &&
			strings.Contains(r.Value, "Files: 1") &&
			strings.Contains(r.Value, "Beginning: PK") &&
			strings.Contains(r.Value, "Error: CRC check failed 0x3e8059d7 != 0x1add145aL")
	})
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

func TestCommunicatingFiles_BundleInfo_EdgeCases(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		name       string
		bundleInfo map[string]any
		expectVal  string
		expectPwd  string
	}{
		{
			name:       "empty bundle info",
			bundleInfo: map[string]any{},
			expectVal:  "",
			expectPwd:  "",
		},
		{
			name: "invalid types in extensions and file_types",
			bundleInfo: map[string]any{
				"extensions": map[string]any{
					"exe": "not a number for exe",
				},
				"file_types": map[string]any{
					"XML": "not a number for xml",
				},
			},
			expectVal: "",
			expectPwd: "",
		},
		{
			name: "invalid bundleInfo type",
			bundleInfo: map[string]any{
				"type":             111,
				"highest_datetime": 222,
				"lowest_datetime":  333,
				"password":         444,
				"error":            555,
				"beginning":        666,
			},
			expectVal: "",
			expectPwd: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

			extractCommunicatingFile(map[string]any{
				"id": "bundle_1234567890abcdef1234567890abcdef1234567890abcdef12345678",
				constants.KeyAttributes: map[string]any{
					"bundle_info": tt.bundleInfo,
				},
			}, exec, gen)

			valFound := false
			pwdFound := false
			for _, r := range exec.Results {
				if r.Type == constants.TypeBundleInfo {
					if r.Value == tt.expectVal {
						valFound = true
					}
				}
				if r.Type == constants.TypePassword {
					if r.Value == tt.expectPwd {
						pwdFound = true
					}
				}
			}

			if tt.expectVal != "" && !valFound {
				t.Fatalf("expected BundleInfo value '%s', got something else or none", tt.expectVal)
			}
			if tt.expectPwd != "" && !pwdFound {
				t.Fatalf("expected Password value '%s', got something else or none", tt.expectPwd)
			}
		})
	}
}

func TestCommunicatingFiles_DebInfoMeta(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/domains/deb.example.com/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "deb.example.com",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	requireResult(t, exec.Results, "deb package info", func(r schema.ModuleResult) bool {
		if r.Type != constants.TypePackageInfo {
			return false
		}
		if !strings.Contains(r.Value, "Version: 1.34.1 (amd64)") {
			return false
		}
		if !strings.Contains(r.Value, "Urgency: medium") {
			return false
		}
		if !strings.Contains(r.Value, "Author: Blablabla <support@lablabla.bla>") {
			return false
		}
		if !strings.Contains(r.Value, "Maintainer: Blablabla <support@blablabla.bla>") {
			return false
		}
		return strings.Contains(r.Value, "Vendor: Blablabla <support@blabla.org>")
	})

	requireResult(t, exec.Results, "deb file script postinst", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileScript && len(r.Tags) > 0 && r.Tags[0] == "postinst"
	})

	requireResult(t, exec.Results, "deb file name", func(r schema.ModuleResult) bool {
		return r.Type == constants.TypeFileName && r.Value == "blabla-desktop"
	})
}

func TestCommunicatingFiles_DebInfoDates(t *testing.T) {
	fixture := loadVTFixture(t, "communicating_files.json")
	mod := setupCommFilesTest(t, "/api/v3/domains/deb.example.com/communicating_files?limit=40", fixture)

	exec := execVTCommFiles(t, mod, constants.FuncGetVTApiDomainCommunicatingFiles, schema.Entity{
		Type:  constants.TypeDomain,
		Value: "deb.example.com",
	})
	if exec.Error != nil {
		t.Fatalf("unexpected error: %s", *exec.Error)
	}

	t.Run("dates", func(t *testing.T) {
		requireResult(t, exec.Results, "deb package build date", func(r schema.ModuleResult) bool {
			return r.Type == constants.TypeDate && r.Value == "Build: 2020-05-16 00:25:05"
		})

		requireResult(t, exec.Results, "deb package oldest date", func(r schema.ModuleResult) bool {
			return r.Type == constants.TypeDate && r.Value == "Oldest Contained File: 2020-05-16 00:08:35"
		})

		requireResult(t, exec.Results, "deb package newest date", func(r schema.ModuleResult) bool {
			return r.Type == constants.TypeDate && r.Value == "Newest Contained File: 2020-05-16 00:25:05"
		})
	})
}

func TestCommunicatingFiles_DebInfo_EdgeCases(t *testing.T) {
	gen := modutil.NewLocalIDGenerator()

	tests := []struct {
		controlVal any
		changeVal  any
		structVal  any
		scriptVal  any
		expectVals map[string]bool
		changeDate string
		name       string
	}{
		{
			name:       "not maps",
			controlVal: 123,
			changeVal:  123,
			structVal:  123,
			scriptVal:  123,
		},
		{
			name:       "missing arch but has version",
			controlVal: map[string]any{"Version": "1.0"},
			expectVals: map[string]bool{"Version: 1.0": true},
		},
		{
			name:       "missing pkgName in control, present in changelog",
			changeVal:  map[string]any{"Package": "fallback-pkg"},
			expectVals: map[string]bool{"fallback-pkg": true},
		},
		{
			name:       "date parsing fallback RFC1123",
			changeDate: "Fri, 15 May 2020 17:25:05 UTC",
			expectVals: map[string]bool{"Build: 2020-05-15 17:25:05": true},
		},
		{
			name:       "date parsing fallback custom",
			changeDate: "Fri, 5 May 2020 17:25:05 -0700",
			expectVals: map[string]bool{"Build: 2020-05-06 00:25:05": true},
		},
		{
			name:       "date parsing unparseable",
			changeDate: "Just a random string",
			expectVals: map[string]bool{"Build: Just a random string": true},
		},
		{
			name:       "contained_files instead of contained_items",
			structVal:  map[string]any{"contained_files": float64(42)},
			expectVals: map[string]bool{"Files: 42": true},
		},
		{
			name:      "invalid script type",
			scriptVal: map[string]any{"postinst": 12345},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &schema.ModuleExecution{Function: constants.FuncGetVTApiDomainCommunicatingFiles}

			debInfo := make(map[string]any)
			if tt.controlVal != nil {
				debInfo["control_metadata"] = tt.controlVal
			}
			if tt.changeVal != nil {
				debInfo["changelog"] = tt.changeVal
			} else if tt.changeDate != "" {
				debInfo["changelog"] = map[string]any{"Date": tt.changeDate}
			}
			if tt.structVal != nil {
				debInfo["structural_metadata"] = tt.structVal
			}
			if tt.scriptVal != nil {
				debInfo["control_scripts"] = tt.scriptVal
			}

			extractCommunicatingFile(map[string]any{
				"id": "deb_edge_" + tt.name,
				constants.KeyAttributes: map[string]any{
					"deb_info": debInfo,
				},
			}, exec, gen)

			for expectVal, shouldExist := range tt.expectVals {
				found := false
				for _, r := range exec.Results {
					if strings.Contains(r.Value, expectVal) {
						found = true
						break
					}
				}
				if found != shouldExist {
					t.Errorf("expected string %q presence to be %v, but was %v", expectVal, shouldExist, found)
				}
			}
		})
	}
}
