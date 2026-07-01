package ip2location

import (
	"strings"
	"sync"
	"testing"

	"github.com/ip2location/ip2location-go/v9"
	"github.com/ip2location/ip2proxy-go/v4"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

var mockGeoRecord = &ip2location.IP2Locationrecord{
	Country_short: "EX",
	Country_long:  "Exampleland",
	Region:        "Exampleshire",
	City:          "Exampleville",
	Latitude:      51.509865,
	Longitude:     -0.118092,
	Zipcode:       "EX1 2AB",
	Timezone:      "+00:00",
	Isp:           "Example ISP Ltd",
	Domain:        "example.net",
	Netspeed:      "DSL",
	Iddcode:       "44",
	Areacode:      "020",
	Mcc:           "234",
	Mnc:           "15",
	Mobilebrand:   "Example Telecom",
	Elevation:     15,
	Usagetype:     "ISP/MOB",
	Addresstype:   "U",
	Category:      "IAB19",
	District:      "Example District",
}

var mockGeoRecordLite = &ip2location.IP2Locationrecord{
	Country_short: "-",
	Country_long:  "This parameter is unavailable for selected data file. Please upgrade the data file.",
	Region:        "-",
	City:          "This parameter is unavailable",
	Latitude:      0.0,
	Longitude:     0.0,
	Elevation:     0.0,
}

var mockASNRecord = &ip2location.IP2Locationrecord{
	Asn:         "12345",
	As:          "Example Org",
	Asdomain:    "example.org",
	Asusagetype: "ORG",
	Ascidr:      "192.0.2.0/24",
}

var mockProxyRecord = &ip2proxy.IP2ProxyRecord{
	IsProxy:      1,
	ProxyType:    "VPN",
	Threat:       "SCANNER/SPAM",
	FraudScore:   "99",
	LastSeen:     "14",
	Provider:     "Example VPN Provider",
	CountryShort: "EX",
	CountryLong:  "Exampleland",
	Region:       "Exampleshire",
	City:         "Exampleville",
	Isp:          "Example ISP Ltd",
	Domain:       "example.net",
	UsageType:    "EDU",
	Asn:          "AS12345",
	As:           "Example Hosting",
}

func requireModuleResult(t *testing.T, results []schema.ModuleResult, resType, expectedValue string) {
	t.Helper()
	for _, r := range results {
		if r.Type == resType && r.Value == expectedValue {
			return
		}
	}
	t.Fatalf("expected result type %q with value %q not found in %d results", resType, expectedValue, len(results))
}

func requireNoModuleResult(t *testing.T, results []schema.ModuleResult, resType string) {
	t.Helper()
	for _, r := range results {
		if r.Type == resType {
			t.Fatalf("did not expect result type %q, but found value %q", resType, r.Value)
		}
	}
}

func requireResultWithContext(t *testing.T, results []schema.ModuleResult, resType, expectedValue, expectedContext string) {
	t.Helper()
	for _, r := range results {
		if r.Type == resType && r.Value == expectedValue && r.Context == expectedContext {
			return
		}
	}
	t.Fatalf("expected result type %q, value %q, context %q not found", resType, expectedValue, expectedContext)
}

func TestModuleInitialization(t *testing.T) {
	originalCheck := checkFileExists
	checkFileExists = func(_ string) bool {
		return true
	}
	defer func() { checkFileExists = originalCheck }()

	m := New()
	if m.Name() != "ip2location" {
		t.Errorf("expected name ip2location, got %q", m.Name())
	}

	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("capabilities error: %v", err)
	}

	foundGeo := false
	for _, f := range caps.Functions {
		if f == constants.FuncGetGeoIP {
			foundGeo = true
		}
	}
	if !foundGeo {
		t.Errorf("expected %q function in capabilities", constants.FuncGetGeoIP)
	}
}

func requireUniqueLocalIDs(t *testing.T, results []schema.ModuleResult) {
	seen := make(map[int]bool)
	for _, res := range results {
		if res.LocalID <= 0 {
			t.Errorf("expected positive LocalID, got %d for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		if seen[res.LocalID] {
			t.Errorf("duplicate LocalID %d found for type %s value %s", res.LocalID, res.Type, res.Value)
		}
		seen[res.LocalID] = true

		if res.Source != nil {
			if res.Source.LocalID <= 0 {
				t.Errorf("expected positive LocalID in source, got %d", res.Source.LocalID)
			}
			if res.Source.LocalID >= res.LocalID {
				t.Errorf("expected source LocalID %d to be strictly less than result LocalID %d (Type: %s, Value: %s)", res.Source.LocalID, res.LocalID, res.Type, res.Value)
			}
		}
	}
}

func TestModule_LocalIDChaining_Geo(t *testing.T) {
	geoQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return mockGeoRecord, nil
	}
	defer func() { geoQueryFunc = defaultGeoQuery }()

	exec := getGeoIP("192.0.2.1", "dummy.bin")
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestModule_LocalIDChaining_ASN(t *testing.T) {
	asnQueryFunc = func(_, _ string) (*ip2location.IP2Locationrecord, error) {
		return mockASNRecord, nil
	}
	defer func() { asnQueryFunc = defaultASNQuery }()

	exec := getIPASN("192.0.2.1", "dummy.bin")
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestModule_LocalIDChaining_Proxy(t *testing.T) {
	proxyQueryFunc = func(_, _ string) (*ip2proxy.IP2ProxyRecord, error) {
		return mockProxyRecord, nil
	}
	defer func() { proxyQueryFunc = defaultProxyQuery }()

	exec := getProxyCheck("192.0.2.1", "dummy.bin")
	if exec.Error != nil {
		t.Fatalf("unexpected error: %v", *exec.Error)
	}

	requireUniqueLocalIDs(t, exec.Results)
}

func TestModule_Capabilities_Empty(t *testing.T) {
	m := &module{
		geoDBPath:   "",
		asnDBPath:   "",
		proxyDBPath: "",
	}
	caps, err := m.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(caps.Functions) != 0 || len(caps.CustomFunctions) != 0 {
		t.Errorf("expected empty capabilities, got %+v", caps)
	}
}

func TestModule_Exec(t *testing.T) {
	m := &module{
		geoDBPath:   "dummy_geo",
		asnDBPath:   "dummy_asn",
		proxyDBPath: "dummy_proxy",
	}
	input := schema.ModuleInput{
		Target: schema.Entity{Value: "192.0.2.1"},
		Functions: []string{
			constants.FuncGetGeoIP,
			constants.FuncGetIPASN,
			constants.FuncGetProxyCheck,
			"unknown_func",
		},
	}
	out, err := m.Exec(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(out.Executions) != 4 {
		t.Fatalf("expected 4 executions, got %d", len(out.Executions))
	}

	for _, ex := range out.Executions {
		if ex.Function == "unknown_func" {
			if ex.Error == nil || !strings.Contains(*ex.Error, "unsupported function") {
				t.Errorf("expected unsupported function error, got %+v", ex)
			}
		}
	}

	mEmpty := &module{}
	outEmpty, errEmpty := mEmpty.Exec(input)
	if errEmpty != nil {
		t.Fatalf("expected no error for empty module, got %v", errEmpty)
	}
	if len(outEmpty.Executions) != 4 {
		t.Fatalf("expected 4 executions for empty module, got %d", len(outEmpty.Executions))
	}
}

func TestResolveDBPath(t *testing.T) {
	originalCheck := checkFileExists
	defer func() { checkFileExists = originalCheck }()

	checkFileExists = func(path string) bool {
		return strings.HasSuffix(path, "LITE.BIN")
	}
	res := resolveDBPath("PREMIUM.BIN", "LITE.BIN")
	if !strings.HasSuffix(res, "LITE.BIN") {
		t.Errorf("expected lite path, got %q", res)
	}

	checkFileExists = func(_ string) bool {
		return false
	}
	res = resolveDBPath("PREMIUM.BIN", "LITE.BIN")
	if res != "" {
		t.Errorf("expected empty path, got %q", res)
	}
}

func TestParseUsageType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"-", "-"},
		{"This parameter is unavailable XYZ", "This parameter is unavailable XYZ"},
		{"COM", "Commercial"},
		{"COM/UNKNOWN", "Commercial / UNKNOWN"},
		{"UNKNOWN", "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			res := ParseUsageType(tt.input)
			if res != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, res)
			}
		})
	}
}

func TestCheckFileExistsImpl(t *testing.T) {
	// Should exist (this test file itself)
	if !checkFileExistsImpl("ip2location_test.go") {
		t.Errorf("expected ip2location_test.go to exist")
	}

	// Should not exist
	if checkFileExistsImpl("this_file_does_not_exist_12345.bin") {
		t.Errorf("expected file not to exist")
	}
}

func TestDefaultQueryImpls_Error(t *testing.T) {
	_, err := defaultGeoQueryImpl("dummy_non_existent.bin", "1.2.3.4")
	if err == nil {
		t.Errorf("expected error from defaultGeoQueryImpl, got nil")
	}

	_, err = defaultASNQueryImpl("dummy_non_existent.bin", "1.2.3.4")
	if err == nil {
		t.Errorf("expected error from defaultASNQueryImpl, got nil")
	}

	_, err = defaultProxyQueryImpl("dummy_non_existent.bin", "1.2.3.4")
	if err == nil {
		t.Errorf("expected error from defaultProxyQueryImpl, got nil")
	}
}

func TestDefaultQueryImpls_Success(t *testing.T) {
	geoOnce = sync.Once{}
	asnOnce = sync.Once{}
	proxyOnce = sync.Once{}

	_, err := defaultGeoQueryImpl("testdata/geo.bin", "192.0.2.1")
	if err != nil {
		t.Errorf("unexpected error from defaultGeoQueryImpl: %v", err)
	}

	_, err = defaultASNQueryImpl("testdata/asn.bin", "192.0.2.1")
	if err != nil {
		t.Errorf("unexpected error from defaultASNQueryImpl: %v", err)
	}

	_, err = defaultProxyQueryImpl("testdata/proxy.bin", "192.0.2.1")
	if err != nil {
		t.Errorf("unexpected error from defaultProxyQueryImpl: %v", err)
	}

	// Test Get_all error path by closing the database and querying again.
	geoDB.Close()
	_, err = defaultGeoQueryImpl("testdata/geo.bin", "192.0.2.1")
	if err == nil {
		t.Errorf("expected error from defaultGeoQueryImpl with closed DB")
	}

	asnDB.Close()
	_, err = defaultASNQueryImpl("testdata/asn.bin", "192.0.2.1")
	if err == nil {
		t.Errorf("expected error from defaultASNQueryImpl with closed DB")
	}

	err = proxyDB.Close()
	if err != nil {
		t.Errorf("failed to close proxy DB: %v", err)
	}
	_, err = defaultProxyQueryImpl("testdata/proxy.bin", "192.0.2.1")
	if err == nil {
		t.Errorf("expected error from defaultProxyQueryImpl with closed DB")
	}
}
