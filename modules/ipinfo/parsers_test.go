package ipinfo

import (
	"strings"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func assertMaxDirty(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}

	getResult := func(typ, val string) *schema.ModuleResult {
		for i, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return &exec.Results[i]
			}
		}
		return nil
	}

	if !hasResult(constants.TypeGeo, "City: AnotherFakeCity | Region: AnotherFakeRegion | Country: AnotherFakeCountry (YY) | Lat/Lon: 1.111100, -1.111100 | Zip: 11111 | TZ: Fake/Timezone_Two") {
		t.Errorf("Missing expected Geo location formatting")
	}
	if !hasResult(constants.TypeDate, "Last Changed: 2000-01-01") {
		t.Errorf("Missing expected Geo or AS Last Changed property")
	}

	verifyMobileLinkage(t, getResult)
	verifyAnonymousLinkage(t, getResult)

	if !hasResult(constants.TypeASN, "AS77777") {
		t.Errorf("Missing ASN node")
	}
}

func verifyMobileLinkage(t *testing.T, getResult func(typ, val string) *schema.ModuleResult) {
	mobileNode := getResult(constants.TypeTag, "mobile")
	if mobileNode == nil {
		t.Errorf("Missing mobile tag")
		return
	}
	if mobileNode.LocalID <= 0 {
		t.Errorf("Mobile node missing LocalID")
		return
	}

	mobileInfo := getResult(constants.TypeInfo, "FakeTelecom (MCC: 999, MNC: 99)")
	if mobileInfo == nil {
		t.Errorf("Missing mobile network info")
	} else if mobileInfo.Source == nil || mobileInfo.Source.LocalID != mobileNode.LocalID {
		t.Errorf("Mobile network info not correctly linked to mobile tag LocalID")
	}
}

func verifyAnonymousLinkage(t *testing.T, getResult func(typ, val string) *schema.ModuleResult) {
	anonNode := getResult(constants.TypeTag, "anonymous")
	if anonNode == nil {
		t.Errorf("Missing anonymous tag")
		return
	}
	if anonNode.LocalID <= 0 {
		t.Errorf("Anonymous node missing LocalID")
		return
	}

	anonInfo := getResult(constants.TypeInfo, "FakeVPN Service")
	if anonInfo == nil {
		t.Errorf("Missing privacy service name")
	} else if anonInfo.Source == nil || anonInfo.Source.LocalID != anonNode.LocalID {
		t.Errorf("Privacy service name not correctly linked to anonymous tag LocalID")
	}

	anonDate := getResult(constants.TypeDate, "Last Seen: 2000-01-01")
	if anonDate == nil {
		t.Errorf("Missing privacy last seen property")
	} else if anonDate.Source == nil || anonDate.Source.LocalID != anonNode.LocalID {
		t.Errorf("Privacy last seen not correctly linked to anonymous tag LocalID")
	}
}

func assertLite(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}
	if !hasResult(constants.TypeGeo, "Country: FakeCountry (XX)") {
		t.Errorf("Missing expected Lite Geo location formatting")
	}
	if !hasResult(constants.TypeASN, "AS99999") {
		t.Errorf("Missing Lite ASN node")
	}
}

func assertNoASN(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ string) bool {
		for _, r := range exec.Results {
			if r.Type == typ {
				return true
			}
		}
		return false
	}
	if hasResult(constants.TypeASN) {
		t.Errorf("Expected no ASN node, but found one")
	}
}

func assertMobileNoObj(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}
	if !hasResult(constants.TypeTag, "mobile") {
		t.Errorf("Expected mobile tag")
	}
	for _, r := range exec.Results {
		if r.Type == constants.TypeInfo {
			t.Errorf("Expected no mobile info, got %v", r.Value)
		}
	}
}

func assertMobileNoName(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}
	if !hasResult(constants.TypeTag, "mobile") {
		t.Errorf("Expected mobile tag")
	}
	if !hasResult(constants.TypeInfo, "MCC: 123, MNC: 45") {
		t.Errorf("Expected mobile info without name, got something else")
	}
}

func assertGeoNoCountry(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}
	if !hasResult(constants.TypeGeo, "Country: XX") {
		t.Errorf("Expected country code as country in Geo node")
	}
}

func assertGeoFlatFull(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}
	expected := "City: FlatCity | Region: FlatRegion | Country: ZZ | Lat/Lon: 1.11,2.22 | Zip: 54321 | TZ: Flat/Zone"
	if !hasResult(constants.TypeGeo, expected) {
		t.Errorf("Expected full flat geo, got something else")
	}
}

func assertAnonNoObj(t *testing.T, exec *schema.ModuleExecution) {
	hasResult := func(typ, val string) bool {
		for _, r := range exec.Results {
			if r.Type == typ && r.Value == val {
				return true
			}
		}
		return false
	}
	if !hasResult(constants.TypeTag, "anonymous") {
		t.Errorf("Expected anonymous tag")
	}
	for _, r := range exec.Results {
		if r.Type == constants.TypeInfo && strings.HasPrefix(r.Value, "anonymous:") {
			t.Errorf("Expected no anonymous info, got %v", r.Value)
		}
	}
}
