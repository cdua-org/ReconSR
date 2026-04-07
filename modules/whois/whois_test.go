package whois

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSafeString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "list of strings",
			input:    []any{"hello", "world"},
			expected: "hello, world",
		},
		{
			name:     "list with empty strings",
			input:    []any{"hello", "", "world"},
			expected: "hello, world",
		},
		{
			name:     "list with non-strings",
			input:    []any{"hello", 123, "world"},
			expected: "hello, world",
		},
		{
			name:     "invalid type",
			input:    123,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeString(tt.input); got != tt.expected {
				t.Errorf("safeString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseWHOIS_ICANN(t *testing.T) {
	rawWHOIS := `
Domain Name: EXAMPLE.COM
Registry Domain ID: 123456789_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example.com
Registrar URL: http://www.example.com
Updated Date: 2023-01-01T12:00:00Z
Creation Date: 2000-01-01T12:00:00Z
Registry Expiry Date: 2025-01-01T12:00:00Z
Registrar: Example Registrar, Inc.
Registrar IANA ID: 9999
Registrar Abuse Contact Email: abuse@example.com
Registrar Abuse Contact Phone: +1.5555555555
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned

Registrant Name: John Doe
Registrant Organization: Doe Inc
Registrant Street: 123 Main St
Registrant City: Anytown
Registrant State/Province: CA
Registrant Postal Code: 12345
Registrant Country: US
Registrant Phone: +1.5551234567
Registrant Email: john@doe.com

Admin Name: Jane Smith
Admin Organization: Smith LLC
Admin Street: 456 Elm St
Admin Phone: +1.5559876543
Admin Email: jane@smith.com

Tech Name: Tech Guy
Tech Organization: Tech Co
Tech Phone: +1.5551112222
Tech Email: tech@tech.com
`

	expected := Metadata{
		RegistrarURL:   "http://www.example.com",
		WhoisServer:    "whois.example.com",
		IANAID:         "9999",
		DNSSEC:         "unsigned",
		CreationDate:   "2000-01-01T12:00:00Z",
		UpdatedDate:    "2023-01-01T12:00:00Z",
		ExpirationDate: "2025-01-01T12:00:00Z",
		NameServers:    []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus:   []string{"clientTransferProhibited https://icann.org/epp#clientTransferProhibited"},
		Registrar: Contact{
			Name: []string{"Example Registrar, Inc."},
		},
		Registrant: Contact{
			Name:         []string{"John Doe"},
			Organization: []string{"Doe Inc"},
			Email:        []string{"john@doe.com"},
			Address:      []string{"123 Main St", "Anytown", "CA", "12345", "US"},
			Phone:        []string{"+1.5551234567"},
		},
		Admin: Contact{
			Name:         []string{"Jane Smith"},
			Organization: []string{"Smith LLC"},
			Email:        []string{"jane@smith.com"},
			Address:      []string{"456 Elm St"},
			Phone:        []string{"+1.5559876543"},
		},
		Tech: Contact{
			Name:         []string{"Tech Guy"},
			Organization: []string{"Tech Co"},
			Email:        []string{"tech@tech.com"},
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

// TestParseWHOIS_EDUCAUSE validates EDUCAUSE tab-indented freeform format
// with org-on-line-1 heuristic (lineIndex==1 without digits → Organization).
func TestParseWHOIS_EDUCAUSE(t *testing.T) {
	rawWHOIS := `Domain Name: TESTUNI.EDU

Registrant:
	Testland University
	42 Campus Drive
	Testville, TS 99001
	US

Administrative Contact:
	Alice Tester
	Testland University
	Admin Bldg Room 101, 42 Campus Drive
	Testville, TS 99001-1234
	US
	+1.5550001111
	alice@testuni.fake

Technical Contact:
	NetOps Team
	Testland University
	NOC Room 202, 42 Campus Drive
	Testville, TS 99001-1234
	US
	+1.5550002222
	noc@testuni.fake

Name Servers:
	NS1.TESTUNI.FAKE
	NS2.TESTUNI.FAKE

Domain record activated:    01-Jan-1990
Domain record last updated: 15-Mar-2026
Domain expires:             31-Dec-2027
`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "01-Jan-1990")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "15-Mar-2026")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "31-Dec-2027")

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.testuni.fake", "ns2.testuni.fake"})

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Testland University"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"42 Campus Drive", "Testville, TS 99001", "US"})

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Alice Tester"})
	assertSlice(t, "Admin.Organization", got.Admin.Organization, []string{"Testland University"})
	assertSlice(t, "Admin.Email", got.Admin.Email, []string{"alice@testuni.fake"})
	assertSlice(t, "Admin.Phone", got.Admin.Phone, []string{"+1.5550001111"})
	assertSlice(t, "Admin.Address", got.Admin.Address,
		[]string{"Admin Bldg Room 101, 42 Campus Drive", "Testville, TS 99001-1234", "US"})

	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"NetOps Team"})
	assertSlice(t, "Tech.Organization", got.Tech.Organization, []string{"Testland University"})
	assertSlice(t, "Tech.Email", got.Tech.Email, []string{"noc@testuni.fake"})
	assertSlice(t, "Tech.Phone", got.Tech.Phone, []string{"+1.5550002222"})
}

// TestParseWHOIS_JPRS1 validates JPRS format 1 (letter-prefixed bracket fields).
func TestParseWHOIS_JPRS1(t *testing.T) {
	rawWHOIS := `[ JPRS database provides information on network administration. ]
Domain Information:
a. [Domain Name]                FAKECORP.CO.JP
g. [Organization]               Fake Corporation
l. [Organization Type]          Corporation
m. [Administrative Contact]     AB12345JP
n. [Technical Contact]          CD67890JP
n. [Technical Contact]          EF11111JP
p. [Name Server]                ns1.fake.example
p. [Name Server]                ns2.fake.example
s. [Signing Key]                
[State]                         Connected (2028/06/30)
[Registered Date]                
[Connected Date]                2015/07/01
[Last Update]                   2026/03/15 10:30:00 (JST)
`

	got := parseWHOIS(rawWHOIS)

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Corporation"})
	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"AB12345JP"})
	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"CD67890JP", "EF11111JP"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.example", "ns2.fake.example"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"Connected (2028/06/30)"})
	assertEq(t, "CreationDate", got.CreationDate, "2015/07/01")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026/03/15 10:30:00 (JST)")
}

// TestParseWHOIS_JPRS2 validates JPRS format 2 (bracket fields without
// letter prefix) including Contact Information with continuation lines.
func TestParseWHOIS_JPRS2(t *testing.T) {
	rawWHOIS := `Domain Information:
[Domain Name]                   FAKESTORE.JP

[Registrant]                    Fake Store Inc.

[Name Server]                   ns1.fakecdn.example
[Name Server]                   ns2.fakecdn.example
[Signing Key]                   

[Created on]                    2005/04/10
[Expires on]                    2028/04/10
[Status]                        Active
[Lock Status]                   DomainTransferLocked
[Last Updated]                  2026/02/20 09:15:00 (JST)

Contact Information:
[Name]                          Proxy Solutions Ltd. Fake
[Email]                         proxy@fakeprivacy.example
[Web Page]                       
[Postal code]                   100-0001
[Postal Address]                Fake Tower 5F, 1-2-3 Marunouchi
                                Chiyoda-ku, Tokyo
[Phone]                         +81.312345678
[Fax]                           +81.312345679
`

	got := parseWHOIS(rawWHOIS)

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Store Inc."})
	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Proxy Solutions Ltd. Fake"})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"proxy@fakeprivacy.example"})
	assertSlice(t, "Registrant.Phone", got.Registrant.Phone, []string{"+81.312345678", "+81.312345679"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address,
		[]string{"100-0001", "Fake Tower 5F, 1-2-3 Marunouchi", "Chiyoda-ku, Tokyo"})

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fakecdn.example", "ns2.fakecdn.example"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"Active", "DomainTransferLocked"})
	assertEq(t, "CreationDate", got.CreationDate, "2005/04/10")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2028/04/10")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026/02/20 09:15:00 (JST)")
}

// TestParseWHOIS_NICMexico validates NIC Mexico format with rpsl-style
// indented sections and DNS: name server format.
func TestParseWHOIS_NICMexico(t *testing.T) {
	rawWHOIS := `Domain Name:       fakeshop.com.mx

Created On:        2010-05-15
Expiration Date:   2028-05-15
Last Updated On:   2026-03-01
Registrar:         FakeRegistrar
URL:               http://www.fakeregistrar.example/

Registrant:
   Name:           Domain Ops
   City:           Faketown
   State:          Fakestate
   Country:        Fakeland

Administrative Contact:
   Name:           Domain Ops
   City:           Faketown
   State:          Fakestate
   Country:        Fakeland

Technical Contact:
   Name:           Domain Ops
   City:           Faketown
   State:          Fakestate
   Country:        Fakeland

Billing Contact:
   Name:           Billing Team
   City:           Otherville
   State:          Otherstate
   Country:        Fakeland

Name Servers:
   DNS:            ns1.fakeshop.example
   DNS:            ns2.fakeshop.example

DNSSEC DS Records:
`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2010-05-15")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2028-05-15")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026-03-01")
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FakeRegistrar"})
	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://www.fakeregistrar.example/")

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fakeshop.example", "ns2.fakeshop.example"})

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Domain Ops"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"Faketown", "Fakestate", "Fakeland"})

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Domain Ops"})
	assertSlice(t, "Admin.Address", got.Admin.Address, []string{"Faketown", "Fakestate", "Fakeland"})

	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Domain Ops"})
	assertSlice(t, "Tech.Address", got.Tech.Address, []string{"Faketown", "Fakestate", "Fakeland"})

	// Billing Contact must not leak into other contacts.
	assertSlice(t, "Billing.Name", got.Billing.Name, []string{"Billing Team"})
	assertSlice(t, "Billing.Address", got.Billing.Address, []string{"Otherville", "Otherstate", "Fakeland"})
}

// TestParseWHOIS_KRNIC validates Korean KRNIC format with Host Name
// name servers and Administrative Contact(AC) fields.
func TestParseWHOIS_KRNIC(t *testing.T) {
	rawWHOIS := `
# ENGLISH

Domain Name                 : fakecompany.co.kr
Registrant                  : Fake Company Ltd
Registrant Address          : 99, Fake-ro, Gangnam-gu, Seoul
Registrant Zip Code         : 06100
Administrative Contact(AC)  : Fake Company Ltd
AC E-Mail                   : domain@fakecompany.example
AC Phone Number             : 02-1234-5678
Registered Date             : 2000. 03. 15.
Last Updated Date           : 2024. 06. 20.
Expiration Date             : 2027. 03. 15.
Publishes                   : Y
Authorized Agency           : FakeAgent Corp.(http://fakeagent.example)
DNSSEC                      : unsigned
Domain Status               : clientTransferProhibited

Primary Name Server
   Host Name                : ns1.fakecompany.example

Secondary Name Server
   Host Name                : ns2.fakecompany.example
   Host Name                : ns3.fakecompany.example
`

	got := parseWHOIS(rawWHOIS)

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Company Ltd"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address,
		[]string{"99, Fake-ro, Gangnam-gu, Seoul", "06100"})

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Fake Company Ltd"})
	assertSlice(t, "Admin.Email", got.Admin.Email, []string{"domain@fakecompany.example"})
	assertSlice(t, "Admin.Phone", got.Admin.Phone, []string{"02-1234-5678"})

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FakeAgent Corp.(http://fakeagent.example)"})

	assertEq(t, "CreationDate", got.CreationDate, "2000. 03. 15.")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2024. 06. 20.")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2027. 03. 15.")
	assertEq(t, "DNSSEC", got.DNSSEC, "unsigned")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"clientTransferProhibited"})

	assertSlice(t, "NameServers", got.NameServers,
		[]string{"ns1.fakecompany.example", "ns2.fakecompany.example", "ns3.fakecompany.example"})
}

func TestParseRDAP(t *testing.T) {
	rdapJSON := `
	{
		"events": [
			{"eventAction": "registration", "eventDate": "2000-01-01T12:00:00Z"},
			{"eventAction": "expiration", "eventDate": "2025-01-01T12:00:00Z"},
			{"eventAction": "last changed", "eventDate": "2023-01-01T12:00:00Z"}
		],
		"status": ["active"],
		"nameservers": [
			{"ldhName": "ns1.example.com"},
			{"ldhName": "ns2.example.com"}
		],
		"entities": [
			{
				"roles": ["registrar"],
				"vcardArray": [
					"vcard",
					[
						["fn", {}, "text", "Example Registrar"],
						["url", {}, "uri", "http://www.example.com"]
					]
				]
			},
			{
				"roles": ["registrant"],
				"vcardArray": [
					"vcard",
					[
						["fn", {}, "text", "John Doe"],
						["org", {}, "text", "Doe Inc"],
						["email", {}, "text", "john@doe.com"],
						["tel", {}, "text", "+1.5551234567"],
						["adr", {}, "text", "123 Main St"]
					]
				]
			}
		]
	}`

	var data map[string]any
	err := json.Unmarshal([]byte(rdapJSON), &data)
	if err != nil {
		t.Fatalf("Failed to unmarshal RDAP JSON: %v", err)
	}

	expected := Metadata{
		CreationDate:   "2000-01-01T12:00:00Z",
		ExpirationDate: "2025-01-01T12:00:00Z",
		UpdatedDate:    "2023-01-01T12:00:00Z",
		DomainStatus:   []string{"active"},
		NameServers:    []string{"ns1.example.com", "ns2.example.com"},
		Registrar: Contact{
			Name: []string{"Example Registrar"},
		},
		RegistrarURL: "http://www.example.com",
		Registrant: Contact{
			Name:         []string{"John Doe"},
			Organization: []string{"Doe Inc"},
			Email:        []string{"john@doe.com"},
			Phone:        []string{"+1.5551234567"},
			Address:      []string{"123 Main St"},
		},
	}

	got := parseRDAP(data)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("parseRDAP() mismatch\nGot:  %+v\nWant: %+v", got, expected)
	}
}

// --- Test helpers ---

func assertEq(t *testing.T, field, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", field, got, want)
	}
}

func assertSlice(t *testing.T, field string, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %v, want %v", field, got, want)
	}
}
