package whois

import "testing"

func TestParseWHOIS_NICAT(t *testing.T) {
	rawWHOIS := `
% Copyright (c)2026 by NIC.AT (1)
% Restricted rights.

domain:         fake.at
registrar:      Fake Registrar GmbH ( https://fake.at/registrar/123 )
registrant:     FAKEREG-NICAT
tech-c:         FAKETECH-NICAT
nserver:        ns1.fake.at
nserver:        ns2.fake.at
admin-c:        FAKEADMIN-NICAT
changed:        20230801 14:51:59
source:         AT-DOM

personname:     Fake Registrant Name
organization:   Fake Org Inc
street address: Fake Street 1
postal code:    1234
city:           Fake City
country:        Austria
phone:          <data not disclosed>
fax-no:         <data not disclosed>
e-mail:         <data not disclosed>
nic-hdl:        FAKEREG-NICAT
changed:        20230801 14:48:50
source:         AT-DOM

personname:     Fake Tech Name
organization:   Fake Tech Org
street address: Tech Street 2
postal code:    4321
city:           Tech City
country:        Austria
phone:          <data not disclosed>
fax-no:         <data not disclosed>
e-mail:         <data not disclosed>
nic-hdl:        FAKETECH-NICAT
changed:        20241002 10:04:57
source:         AT-DOM
`
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
