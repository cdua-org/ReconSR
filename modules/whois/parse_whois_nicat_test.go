package whois

import "testing"

func TestParseWHOIS_NICAT(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/nicat.txt")
	got := parseWHOIS(rawWHOIS)

	assertEq(t, "UpdatedDate", got.UpdatedDate, "20230801 14:51:59")

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.at", "ns2.fake.at"})
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Registrar GmbH ( https://fake.at/registrar/123 )"})
	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"FAKETECH-NICAT"})
	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"FAKEADMIN-NICAT"})

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Fake Registrant Name", "Fake Tech Name"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"FAKEREG-NICAT", "Fake Org Inc", "Fake Tech Org"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{
		"Fake Street 1", "1234", "Fake City", "Austria",
		"Tech Street 2", "4321", "Tech City",
	})
}
