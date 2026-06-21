package virustotal

import (
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/schema"
)

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
