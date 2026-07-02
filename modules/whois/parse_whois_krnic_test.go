package whois

import (
	"testing"
)

func TestParseWHOIS_KRNIC(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/krnic.txt")
	got := parseWHOIS(rawWHOIS)

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Company Ltd"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address,
		[]string{"99, Fake-ro, Gangnam-gu, Seoul", "06100"})

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Admin Company Ltd"})
	assertSlice(t, "Admin.Email", got.Admin.Email, []string{"domain@fakecompany.example"})
	assertSlice(t, "Admin.Phone", got.Admin.Phone, []string{"02-1234-5678"})

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FakeAgent Corp.(http://fakeagent.example)"})

	assertEq(t, "CreationDate", got.CreationDate, "2000. 03. 15.")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2024. 06. 20.")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2027. 03. 15.")
	assertEq(t, "DNSSEC", got.DNSSEC, "unsigned")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"clientDeleteProhibited", "clientUpdateProhibited"})

	assertSlice(t, "NameServers", got.NameServers,
		[]string{"ns1.fakecompany.example", "ns2.fakecompany.example", "ns3.fakecompany.example"})
}
