// file: parse_whois_test.go

package whois

import (
	"reflect"
	"testing"
)

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

// TestParseWHOIS_NICIT validates Italian WHOIS format with bare-word headers,
// multi-line indented addresses, and independent scopes for contacts.
func TestParseWHOIS_NICIT(t *testing.T) {
	rawWHOIS := `
Domain:             fake.it
Status:             ok
Signed:             no
Created:            2000-01-01 00:00:00
Last Update:        2024-05-10 12:00:00
Expire Date:        2027-01-01

Registrant
  Organization:     Fake Company S.p.A.
  Address:          Via Luigi 10
                    ROMA
                    00100
                    RM
                    IT
  Created:          2005-02-15 10:00:00
  Last Update:      2020-03-20 15:00:00

Admin Contact
  Name:             Mario Rossi
  Organization:     Fake Company S.p.A
  Address:          Via Napoli 20
                    MILANO
                    20100
                    MI
                    IT
  Created:          2005-02-15 10:05:00
  Last Update:      2018-09-10 09:30:00

Technical Contacts
  Name:             Tech Support
  Organization:     NetProvider Srl
  Address:          Via Torino 5
                    TORINO
                    10100
                    TO
                    IT
  Created:          2010-10-10 00:00:00

Registrar
  Organization:     NetReg S.r.l.
  Name:             NETREG-IT
  Web:              http://www.netreg.example.it
  DNSSEC:           no

Nameservers
  ns1.fake.example.it
  ns2.fake.example.it
`

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
	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://www.netreg.example.it")

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.example.it", "ns2.fake.example.it"})
}

// TestParseWHOIS_CN validates Chinese WHOIS format
func TestParseWHOIS_CN(t *testing.T) {
	rawWHOIS := `
Domain Name: fake.cn
ROID: 20030312s10001s00062053-cn
Domain Status: clientDeleteProhibited
Domain Status: clientTransferProhibited
Registrant: Fake LLC
Registrant Contact Email: fake@fake.cn
Sponsoring Registrar: Fake Beijing Registrar Co. Ltd
Name Server: ns1.fake.cn
Name Server: ns2.fake.cn
Name Server: ns3.fake.cn
Name Server: ns4.fake.cn
Registration Time: 2003-03-17 12:20:05
Expiration Time: 2029-03-17 12:48:36
DNSSEC: unsigned
`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2003-03-17 12:20:05")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2029-03-17 12:48:36")
	assertEq(t, "DNSSEC", got.DNSSEC, "unsigned")

	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"clientDeleteProhibited", "clientTransferProhibited"})
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Beijing Registrar Co. Ltd"})

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake LLC"})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"fake@fake.cn"})

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.cn", "ns2.fake.cn", "ns3.fake.cn", "ns4.fake.cn"})
}
