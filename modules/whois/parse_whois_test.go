package whois

import (
	"embed"
	"reflect"
	"testing"
)

//go:embed testdata/*.txt
var testdataFS embed.FS

func loadFixture(t *testing.T, fileName string) string {
	t.Helper()

	data, err := testdataFS.ReadFile(fileName)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fileName, err)
	}

	return string(data)
}

func TestParseWHOIS_ICANN(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/icann.txt")

	expected := Metadata{
		RegistrarURL:   "http://www.example.com",
		WhoisServer:    "whois.icann.example.com",
		IANAID:         "9999",
		DNSSEC:         "unsigned",
		CreationDate:   "2000-01-01T12:00:00Z",
		UpdatedDate:    "2023-01-01T12:00:00Z",
		ExpirationDate: "2025-01-01T12:00:00Z",
		NameServers:    []string{"ns1.icann.example.com", "ns2.example.com"},
		DomainStatus:   []string{"serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited"},
		Registrar: Contact{
			Name: []string{"Example Registrar, Inc."},
		},
		Registrant: Contact{
			Name:         []string{"John Doe"},
			Organization: []string{"Doe Inc"},
			Email:        []string{"john@doe.example.com"},
			Address:      []string{"123 Main St", "Anytown", "CA", "12345", "US"},
			Phone:        []string{"+1.5551234567"},
		},
		Admin: Contact{
			Name:         []string{"Jane Smith"},
			Organization: []string{"Smith LLC"},
			Email:        []string{"jane@smith.example.com"},
			Address:      []string{"456 Elm St"},
			Phone:        []string{"+1.5559876543"},
		},
		Tech: Contact{
			Name:         []string{"Tech Guy"},
			Organization: []string{"Tech Co"},
			Email:        []string{"tech@tech.example.com"},
			Phone:        []string{"+1.5551112222"},
		},
		Abuse: Contact{
			Email: []string{"abuse@example.com"},
			Phone: []string{"+1.5555555555"},
		},
	}

	got := parseWHOIS(rawWHOIS)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("parseWHOIS(ICANN) mismatch\nGot:  %+v\nWant: %+v", got, expected)
	}
}

func TestParseWHOIS_EDUCAUSE(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/educause.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "01-Jan-1990")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "15-Mar-2026")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "31-Dec-2027")

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.testuni.example", "ns2.testuni.example"})

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Testland University"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"42 Campus Drive", "Testville, TS 99001", "US"})

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Alice Tester"})
	assertSlice(t, "Admin.Organization", got.Admin.Organization, []string{"Campus Governance Group"})
	assertSlice(t, "Admin.Email", got.Admin.Email, []string{"alice@testuni.example"})
	assertSlice(t, "Admin.Phone", got.Admin.Phone, []string{"+1.5550001111"})
	assertSlice(t, "Admin.Address", got.Admin.Address,
		[]string{"Admin Bldg Room 101, 42 Campus Drive", "Testville, TS 99001-1234", "US"})

	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"NetOps Team"})
	assertSlice(t, "Tech.Organization", got.Tech.Organization, []string{"Mock Network Services"})
	assertSlice(t, "Tech.Email", got.Tech.Email, []string{"noc@testuni.example"})
	assertSlice(t, "Tech.Phone", got.Tech.Phone, []string{"+1.5550002222"})
}

func TestParseWHOIS_IANA(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/iana.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2014-11-20")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-04-11")

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Registry Inc."})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"123 Fake Street", "Faketown CA 99999", "Example Republic"})
	assertSlice(t, "Registrant.Phone", got.Registrant.Phone, nil)

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Fake Admin"})
	assertSlice(t, "Admin.Organization", got.Admin.Organization, []string{"Admin Relay Group"})
	assertSlice(t, "Admin.Address", got.Admin.Address, []string{"456 Admin Blvd", "Adminville NY 10001", "Fixture Federation"})
	assertSlice(t, "Admin.Phone", got.Admin.Phone, []string{"+1 555 123 4567"})

	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Fake Tech"})
	assertSlice(t, "Tech.Organization", got.Tech.Organization, []string{"Tech Transit Unit"})
	assertSlice(t, "Tech.Address", got.Tech.Address, []string{"789 Tech Lane", "Techcity NY 10002", "Sample Union"})
	assertSlice(t, "Tech.Phone", got.Tech.Phone, []string{"+1 555 987 6543"})

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.root-fake.example.net", "ns2.root-fake.example.net"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"ACTIVE"})
}

func TestParseWHOIS_AU(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/au.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026-02-23T11:19:19Z")
	assertEq(t, "RegistrarURL", got.RegistrarURL, "https://www.fake.example/contact")
	assertEq(t, "WhoisServer", got.WhoisServer, "whois.auda.org.au")
	assertEq(t, "DNSSEC", got.DNSSEC, "unsigned")

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Registrar Pty Ltd"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"serverRenewProhibited https://identitydigital.au/whois-status-codes#serverRenewProhibited"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.auda-fake.example.org", "ns2.auda-fake.example.org"})

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Fake Reg Contact"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"FAKE COMPANY PTY LTD"})
	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Fake Tech Contact"})
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@fake.example"})
	assertSlice(t, "Abuse.Phone", got.Abuse.Phone, []string{"+61.123456789"})
}

func TestParseWHOIS_UA_Noise(t *testing.T) {
	rawWHOIS := `
domain:           ua.test.example
mnt-by:           ua.fake
status:           ok

% Registrar:
% ==========
registrar:        ua.fake
organization:     Fake Registrar Inc.

% Registrant:
% ===========
person:           n/a
person-loc:       Domain Administrator
organization-loc: Mock Privacy Shield LLC
address:          n/a
address-loc:      1600 Amphitheatre Parkway
`

	got := parseWHOIS(rawWHOIS)

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"ua.fake"})
	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Domain Administrator"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Mock Privacy Shield LLC"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"1600 Amphitheatre Parkway"})
}

func TestParseWHOIS_XYZ_Noise(t *testing.T) {
	rawWHOIS := `Domain Name: TEST.EXAMPLE
Registrar: Fake Registrar, Inc.
Registrar IANA ID: 999
Registrar URL:
Updated Date: 2025-11-11T12:00:30.0Z
Name Server: NS1.TEST.EXAMPLE

>>> IMPORTANT INFORMATION ABOUT THE DEPLOYMENT OF RDAP: please visit
https://www.example.com/rdap <<<

The Whois and RDAP services are provided by Fake Registry.`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "RegistrarURL", got.RegistrarURL, "")
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Registrar, Inc."})
	assertEq(t, "IANAID", got.IANAID, "999")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-11-11T12:00:30.0Z")
}

func TestParseWHOIS_ICANN_Footer(t *testing.T) {
	rawWHOIS := `   Domain Name: TEST.EXAMPLE
   Registry Domain ID: 12345_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.fakeregistrar.example.com
   Registrar URL: http://www.fakeregistrar.example.com
   Updated Date: 2019-09-09T15:39:04Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2028-09-14T04:00:00Z
   Registrar: FakeRegistrar Inc.
   Registrar IANA ID: 292
   Registrar Abuse Contact Email: abuse@fakeregistrar.example.com
   Registrar Abuse Contact Phone: +1.2085551234
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: NS1.TEST.EXAMPLE
   Name Server: NS2.TEST.EXAMPLE
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2026-04-07T13:32:18Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar.  Users may consult the sponsoring registrar's Whois database to
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes.

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1997-09-15T04:00:00Z")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2019-09-09T15:39:04Z")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2028-09-14T04:00:00Z")
	assertEq(t, "WhoisServer", got.WhoisServer, "whois.fakeregistrar.example.com")
	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://www.fakeregistrar.example.com")
	assertEq(t, "IANAID", got.IANAID, "292")
	assertEq(t, "DNSSEC", got.DNSSEC, "unsigned")

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FakeRegistrar Inc."})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.test.example", "ns2.test.example"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{
		"clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
		"serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
	})

	assertSlice(t, "Registrar.Organization", got.Registrar.Organization, nil)
	assertSlice(t, "Registrar.Address", got.Registrar.Address, nil)
	assertSlice(t, "Registrant.Name", got.Registrant.Name, nil)
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, nil)
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@fakeregistrar.example.com"})
	assertSlice(t, "Abuse.Phone", got.Abuse.Phone, []string{"+1.2085551234"})
}

func TestParseWHOIS_WhoisServerHTTP_Noise(t *testing.T) {
	rawWHOIS := `
Domain Name: fake.org
Registry Domain ID: REDACTED
Registrar WHOIS Server: http://whois.fakeregistrar.example.com
Registrar URL: http://www.fakeregistrar.example.com
Updated Date: 2025-12-17T09:26:13Z
Creation Date: 2001-01-13T00:12:14Z
Registry Expiry Date: 2027-01-13T00:12:14Z
Registrar: FakeRegistrar Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abuse@fakeregistrar.example.com
Registrar Abuse Contact Phone: +1.2083895740
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Name Server: ns0.fake.org
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://icann.org/wicf/
>>> Last update of WHOIS database: 2026-04-07T14:44:13Z <<<

For more information on Whois status codes, please visit https://icann.org/epp
`
	got := parseWHOIS(rawWHOIS)

	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://www.fakeregistrar.example.com")

	assertEq(t, "WhoisServer", got.WhoisServer, "whois.fakeregistrar.example.com")
}
