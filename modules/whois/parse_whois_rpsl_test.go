package whois

import "testing"

func TestParseWHOIS_NICMexico(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/nicmexico.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2010-05-15")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2028-05-15")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026-03-01")
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FakeRegistrar"})
	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://www.fakeregistrar.example/")

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fakeshop.example.net", "ns2.fakeshop.example.net"})

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Registry Desk Uno"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"Faketown Norte", "Northstate Uno", "Fakeland Norte"})

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Admin Desk Dos"})
	assertSlice(t, "Admin.Address", got.Admin.Address, []string{"Adminpolis Sur", "Southstate Dos", "Fakeland Sur"})

	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Tech Crew Tres"})
	assertSlice(t, "Tech.Address", got.Tech.Address, []string{"Techvale Este", "Eaststate Tres", "Fakeland Este"})

	assertSlice(t, "Billing.Name", got.Billing.Name, []string{"Billing Team"})
	assertSlice(t, "Billing.Address", got.Billing.Address, []string{"Otherville", "Otherstate", "Fakeland Oeste"})
}

func TestParseWHOIS_NICIT(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/nicit.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2000-01-01 00:00:00")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2024-05-10 12:00:00")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2027-01-01")
	assertEq(t, "DNSSEC", got.DNSSEC, "no")

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Company S.p.A."})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"Via Luigi 10", "ROMA", "00100", "RM", "IT"})

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Mario Rossi"})
	assertSlice(t, "Admin.Organization", got.Admin.Organization, []string{"Fake Company S.p.A"})
	assertSlice(t, "Admin.Address", got.Admin.Address, []string{"Via Napoli 20", "MILANO", "20100", "MI", "IT"})

	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Tech Support"})
	assertSlice(t, "Tech.Organization", got.Tech.Organization, []string{"NetProvider Srl"})
	assertSlice(t, "Tech.Address", got.Tech.Address, []string{"Via Torino 5", "TORINO", "10100", "TO", "IT"})

	assertSlice(t, "Registrar.Organization", got.Registrar.Organization, []string{"NetReg S.r.l."})
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"NETREG-IT"})
	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://www.netreg.example.com")

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.it.test.example", "ns2.it.test.example"})
}

func TestParseWHOIS_RU(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/ru.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2000-01-01T10:00:00Z")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2028-01-01T10:00:00Z")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026-04-07T07:53:01Z")

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FAKE-REGISTRAR-RU"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"FAKE, LLC."})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.ru.test.example", "ns2.ru.test.example"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"REGISTERED, DELEGATED, VERIFIED"})
}

func TestParseWHOIS_FR(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/fr.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2001-02-01T23:00:00Z")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2026-10-14T15:12:55Z")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-03-30T12:17:54.513642Z")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"ACTIVE", "serverUpdateProhibited", "clientTransferProhibited"})
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FAKE REGISTRAR"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fr.test.example", "ns2.fr.test.example"})
}

func TestParseWHOIS_NL(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/nl.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1996-07-22")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-03-13")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"active"})
	assertEq(t, "DNSSEC", got.DNSSEC, "yes")
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake B.V."})
	assertSlice(t, "Registrar.Address", got.Registrar.Address, []string{"Fake Street 123", "1234AB Faketown", "Netherlands"})
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@nl.test.example"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.nl.test.example", "ns2.nl.test.example"})
}

func TestParseWHOIS_PL(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/pl.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1998.04.28 13:00:00")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026.02.18 14:22:40")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2027.04.27 14:00:00")
	assertEq(t, "DNSSEC", got.DNSSEC, "Unsigned")
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.pl.test.example", "ns2.pl.test.example"})

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Registrar Sp. z o.o."})
	assertSlice(t, "Registrar.Address", got.Registrar.Address, []string{"ul. Fake 4", "70-653 Faketown", "Polska/Poland"})
	assertSlice(t, "Registrar.Phone", got.Registrar.Phone, []string{"+48.123456789"})
	assertEq(t, "RegistrarURL", got.RegistrarURL, "https://pl.test.example/")
	assertSlice(t, "Registrar.Email", got.Registrar.Email, []string{"domena@pl.test.example"})
}

func TestParseWHOIS_CZ(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/cz.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "07.10.1996 02:00:00")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "05.09.2022 14:21:11")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "29.10.2026")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"Sponsoring registrar change forbidden"})

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Registrant Organization"})
	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Jane Doe"})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"owner@cz.test.example"})

	assertSlice(t, "Admin.Organization", got.Admin.Organization, []string{"Fake Admin Organization"})
	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"John Smith"})
	assertSlice(t, "Admin.Email", got.Admin.Email, []string{"admin@cz.test.example"})

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.cz.test.example", "ns2.cz.test.example"})
}

func TestParseWHOIS_AR(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/ar.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1999-06-08 00:00:00")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-06-09 15:37:19.837308")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2026-07-08 00:00:00")

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"FAKE CORPORATE INC."})
	assertSlice(t, "Registrant.Name", got.Registrant.Name, nil)

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.ar.test.example", "ns2.ar.test.example"})
}

func TestParseWHOIS_FI(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/fi.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1.1.1991 00:00:00")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "17.3.2022 13:30:38")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "31.8.2030 00:00:00")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"Registered"})

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fi.test.example", "ns2.fi.test.example", "ns-secondary.fi.test.example"})
	assertEq(t, "DNSSEC", got.DNSSEC, "no")

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Fake Registrant"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"Fake Street 1", "00100", "Fake City", "Finland"})
	assertSlice(t, "Registrant.Phone", got.Registrant.Phone, []string{"+358.123456789"})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"admin@fi.test.example"})

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Registrar"})
}
