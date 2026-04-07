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

// TestParseWHOIS_RU validates Russian TCI WHOIS format (.ru, .su, .rf)
func TestParseWHOIS_RU(t *testing.T) {
	rawWHOIS := `% TCI Whois Service. Terms of use:
% https://tcinet.ru/documents/whois_ru_rf.pdf (in Russian)
% https://tcinet.ru/documents/whois_su.pdf (in Russian)

domain:        FAKEDOMAIN.RU
nserver:       ns1.fakedomain.ru. 192.0.2.1, 2001:db8::1
nserver:       ns2.fakedomain.ru. 198.51.100.1, 2001:db8:0:1::1
state:         REGISTERED, DELEGATED, VERIFIED
org:           FAKE, LLC.
taxpayer-id:   1234567890
registrar:     FAKE-REGISTRAR-RU
admin-contact: https://www.fake-nic.ru/whois
created:       2000-01-01T10:00:00Z
paid-till:     2028-01-01T10:00:00Z
free-date:     2028-02-01
source:        TCI

Last updated on 2026-04-07T07:53:01Z
`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2000-01-01T10:00:00Z")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2028-01-01T10:00:00Z")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026-04-07T07:53:01Z")

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FAKE-REGISTRAR-RU"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"FAKE, LLC."})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fakedomain.ru", "ns2.fakedomain.ru"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"REGISTERED, DELEGATED, VERIFIED"})
}

// TestParseWHOIS_IANA validates IANA root zone whois format.
func TestParseWHOIS_IANA(t *testing.T) {
	rawWHOIS := `% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org
% This query returned 1 object

domain:       FAKE

organisation: Fake Registry Inc.
address:      123 Fake Street
address:      Faketown CA 99999
address:      United States of America (the)

contact:      administrative
name:         Fake Admin
organisation: Fake LLC
address:      456 Admin Blvd
address:      Adminville NY 10001
address:      United States of America (the)
phone:        +1 555 123 4567
fax-no:       +1 555 123 4568
e-mail:       admin@fake.example

contact:      technical
name:         Fake Tech
organisation: Fake LLC
address:      789 Tech Lane
address:      Techcity NY 10002
address:      United States of America (the)
phone:        +1 555 987 6543
fax-no:       +1 555 987 6544
e-mail:       tech@fake.example

nserver:      NS1.FAKE.EXAMPLE 2001:db8::1 192.0.2.1
nserver:      NS2.FAKE.EXAMPLE 2001:db8::2 192.0.2.2

status:       ACTIVE
remarks:      Registration information: https://www.fake.example

created:      2014-11-20
changed:      2025-04-11
source:       IANA`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2014-11-20")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-04-11")

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Registry Inc."})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"123 Fake Street", "Faketown CA 99999", "United States of America (the)"})
	assertSlice(t, "Registrant.Phone", got.Registrant.Phone, nil)

	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Fake Admin"})
	assertSlice(t, "Admin.Organization", got.Admin.Organization, []string{"Fake LLC"})
	assertSlice(t, "Admin.Address", got.Admin.Address, []string{"456 Admin Blvd", "Adminville NY 10001", "United States of America (the)"})
	assertSlice(t, "Admin.Phone", got.Admin.Phone, []string{"+1 555 123 4567"})

	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Fake Tech"})
	assertSlice(t, "Tech.Organization", got.Tech.Organization, []string{"Fake LLC"})
	assertSlice(t, "Tech.Address", got.Tech.Address, []string{"789 Tech Lane", "Techcity NY 10002", "United States of America (the)"})
	assertSlice(t, "Tech.Phone", got.Tech.Phone, []string{"+1 555 987 6543"})

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.example", "ns2.fake.example"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"ACTIVE"})
}

// TestParseWHOIS_AU validates Australian .au WHOIS format.
func TestParseWHOIS_AU(t *testing.T) {
	rawWHOIS := `Domain Name: fake.com.au
Registry Domain ID: 123456789-AU
Registrar WHOIS Server: whois.auda.org.au
Registrar URL: https://www.fake.example/contact
Last Modified: 2026-02-23T11:19:19Z
Registrar Name: Fake Registrar Pty Ltd
Registrar Abuse Contact Email: abuse@fake.example
Registrar Abuse Contact Phone: +61.123456789
Reseller Name:
Status: serverRenewProhibited https://identitydigital.au/whois-status-codes#serverRenewProhibited
Status Reason: Not Currently Eligible For Renewal
Registrant Contact ID: ce413d96bfdb-AU
Registrant Contact Name: Fake Reg Contact
Tech Contact ID: a49ec9b0b96a-AU
Tech Contact Name: Fake Tech Contact
Name Server: ns1.fake.example
Name Server: ns2.fake.example
DNSSEC: unsigned
Registrant: FAKE COMPANY PTY LTD
Registrant ID: ACN 123456789
Eligibility Type: Company`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026-02-23T11:19:19Z")
	assertEq(t, "RegistrarURL", got.RegistrarURL, "https://www.fake.example/contact")
	assertEq(t, "WhoisServer", got.WhoisServer, "whois.auda.org.au")
	assertEq(t, "DNSSEC", got.DNSSEC, "unsigned")

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Registrar Pty Ltd"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"serverRenewProhibited https://identitydigital.au/whois-status-codes#serverRenewProhibited"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.example", "ns2.fake.example"})

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Fake Reg Contact"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"FAKE COMPANY PTY LTD"})
	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Fake Tech Contact"})
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@fake.example"})
	assertSlice(t, "Abuse.Phone", got.Abuse.Phone, []string{"+61.123456789"})
}

// TestParseWHOIS_FR validates French .fr WHOIS format (AFNIC).
func TestParseWHOIS_FR(t *testing.T) {
	rawWHOIS := `domain:      fake.fr
status:      ACTIVE
eppstatus:   serverUpdateProhibited
eppstatus:   serverTransferProhibited
holder-c:    FAKE1-FRNIC
admin-c:     FAKE2-FRNIC
tech-c:      FAKE3-FRNIC
registrar:   FAKE REGISTRAR
Expiry Date: 2026-10-14T15:12:55Z
created:     2001-02-01T23:00:00Z
+last-update: 2025-03-30T12:17:54.513642Z
source:      FRNIC

nserver:     ns1.fake.fr
nserver:     ns2.fake.fr
source:      FRNIC

nic-hdl:     FAKE1-FRNIC
type:        ORGANIZATION
contact:     FAKE ORG
address:     123 Fake Street
address:     75000 Paris
country:     FR
phone:       +33.123456789
e-mail:      holder@fake.fr`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2001-02-01T23:00:00Z")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2026-10-14T15:12:55Z")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-03-30T12:17:54.513642Z")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"ACTIVE", "serverUpdateProhibited", "serverTransferProhibited"})
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FAKE REGISTRAR"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.fr", "ns2.fake.fr"})
}

// TestParseWHOIS_BR validates Brazilian .br WHOIS format.
func TestParseWHOIS_BR(t *testing.T) {
	rawWHOIS := `domain:      fake.com.br
owner:       Fake S.A.
ownerid:     12.345.678/0001-99
responsible: Contato da Entidade
country:     BR
owner-c:     FAK12
tech-c:      TEC34
nserver:     ns1.fake.com.br
created:     19960424 #7137
changed:     20240827
expires:     20340424
status:      published

nic-hdl-br:  FAK12
person:      Admin Contact
e-mail:      admin@fake.com.br

nic-hdl-br:  TEC34
person:      Tech Contact
e-mail:      tech@fake.com.br`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "19960424 #7137")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "20240827")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "20340424")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"published"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.com.br"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake S.A.", "12.345.678/0001-99"})
	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Admin Contact"})
	assertSlice(t, "Admin.Email", got.Admin.Email, []string{"admin@fake.com.br"})
	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Tech Contact"})
	assertSlice(t, "Tech.Email", got.Tech.Email, []string{"tech@fake.com.br"})
}

// TestParseWHOIS_NL validates Dutch .nl WHOIS format (SIDN).
func TestParseWHOIS_NL(t *testing.T) {
	rawWHOIS := `Domain name: fake.nl
Status:      active

Registrar:
   Fake B.V.
   Fake Street 123
   1234AB Faketown
   Netherlands

Abuse Contact:
   abuse@fake.nl

DNSSEC:      yes

Domain nameservers:
   ns1.fake.nl
   ns2.fake.nl

Creation Date: 1996-07-22

Updated Date: 2025-03-13

Record maintained by: SIDN BV`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1996-07-22")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-03-13")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"active"})
	assertEq(t, "DNSSEC", got.DNSSEC, "yes")
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake B.V."})
	assertSlice(t, "Registrar.Address", got.Registrar.Address, []string{"Fake Street 123", "1234AB Faketown", "Netherlands"})
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@fake.nl"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.nl", "ns2.fake.nl"})
}

// TestParseWHOIS_PL validates Polish .pl WHOIS format (NASK).
func TestParseWHOIS_PL(t *testing.T) {
	rawWHOIS := `DOMAIN NAME:           fake.pl
registrant type:       organization
nameservers:           ns1.fake.pl. [192.0.2.1]
                       ns2.fake.pl. [198.51.100.1]
created:               1998.04.28 13:00:00
last modified:         2026.02.18 14:22:40
renewal date:          2027.04.27 14:00:00

option created:        2026.02.10 10:51:12
option expiration date:2029.02.10 10:51:12

dnssec:                Unsigned

REGISTRAR:
Fake Registrar Sp. z o.o.
ul. Fake 4
70-653 Faketown
Polska/Poland
Tel: +48.123456789
https://fake.pl/
domena@fake.pl`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1998.04.28 13:00:00")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026.02.18 14:22:40")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2027.04.27 14:00:00") // Should NOT be 2029.02.10
	assertEq(t, "DNSSEC", got.DNSSEC, "Unsigned")
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.pl", "ns2.fake.pl"})

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Registrar Sp. z o.o."})
	assertSlice(t, "Registrar.Address", got.Registrar.Address, []string{"ul. Fake 4", "70-653 Faketown", "Polska/Poland"})
	assertSlice(t, "Registrar.Phone", got.Registrar.Phone, []string{"+48.123456789"})
	assertEq(t, "RegistrarURL", got.RegistrarURL, "https://fake.pl/")
	assertSlice(t, "Registrar.Email", got.Registrar.Email, []string{"domena@fake.pl"})
}

// TestParseWHOIS_CZ validates Czech .cz WHOIS format (CZ.NIC).
func TestParseWHOIS_CZ(t *testing.T) {
	rawWHOIS := `
domain:       fake.cz
registrant:   REG-ID-123
admin-c:      ADM-ID-456
nsset:        NS-SET-789
registrar:    REG-CZ-FAKE
status:       Sponsoring registrar change forbidden
registered:   07.10.1996 02:00:00
changed:      05.09.2022 14:21:11
expire:       29.10.2026

contact:      REG-ID-123
org:          Fake Registrant Organization
name:         Jane Doe
address:      Street 1
address:      City A
address:      12345
address:      CZ
e-mail:       owner@fake.cz

contact:      ADM-ID-456
org:          Fake Admin Organization
name:         John Smith
address:      Street 2
address:      City B
address:      67890
address:      CZ
e-mail:       admin@fake.cz

nsset:        NS-SET-789
nserver:      ns1.fake.cz (1.2.3.4, 2a02:598::1)
nserver:      ns2.fake.cz (5.6.7.8, 2a02:598::2)
`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "07.10.1996 02:00:00")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "05.09.2022 14:21:11")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "29.10.2026")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"Sponsoring registrar change forbidden"})

	// Handle descriptors (e.g., REG-ID-123) are relational IDs used for cross-referencing and must be excluded from Organization fields.
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Registrant Organization"})
	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Jane Doe"})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"owner@fake.cz"})

	// The 'admin-c' field in the domain header maps the specific 'contact:' block that should be assigned to the Administrative role.
	assertSlice(t, "Admin.Organization", got.Admin.Organization, []string{"Fake Admin Organization"})
	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"John Smith"})
	assertSlice(t, "Admin.Email", got.Admin.Email, []string{"admin@fake.cz"})

	// Nameservers in the CZ.NIC registry often append glue records or IP addresses in parentheses which require stripping.
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.cz", "ns2.fake.cz"})
}

// TestParseWHOIS_AR validates Argentinian .ar WHOIS format (NIC Argentina).
func TestParseWHOIS_AR(t *testing.T) {
	rawWHOIS := `
domain:      fake.com.ar
registrant:  50037928906
registrar:   nicar
registered:  1999-06-08 00:00:00
changed:     2025-06-09 15:37:19.837308
expire:      2026-07-08 00:00:00

contact:     50037928906
name:        FAKE CORPORATE INC.
registrar:   nicar
created:     2013-10-29 00:00:00
changed:     2026-03-26 14:55:08.507049

nserver:     ns1.fake.com.ar ()
nserver:     ns2.fake.com.ar ()
`

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1999-06-08 00:00:00")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-06-09 15:37:19.837308")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2026-07-08 00:00:00")

	// The numeric handle (CUIT/Tax ID) appearing in 'registrant' and 'contact' fields is a relational ID and must be excluded from Organization names to ensure data cleanliness.
	// In NIC.ar WHOIS, corporate entities are often listed under the 'name' field without an accompanying 'org' field; these should be mapped to Organization.
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"FAKE CORPORATE INC."})
	assertSlice(t, "Registrant.Name", got.Registrant.Name, nil)

	// The Argentinian registry frequently appends empty parentheses '()' to name server hostnames, which must be stripped during parsing.
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.com.ar", "ns2.fake.com.ar"})
}

// TestParseWHOIS_UA_Noise validates that Ukrainian .ua WHOIS decorative comments and 'n/a' placeholders are not captured as data.
func TestParseWHOIS_UA_Noise(t *testing.T) {
	rawWHOIS := `
domain:           fake.com.ua
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
organization-loc: Fake LLC
address:          n/a
address-loc:      1600 Amphitheatre Parkway
`

	got := parseWHOIS(rawWHOIS)

	// Lines beginning with '%' are comments or structural delimiters in registries like Hostmaster.ua and must be excluded from metadata to prevent field corruption.
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"ua.fake"})

	// Placeholder values such as 'n/a' represent missing information and should be ignored during parsing to ensure only valid, actionable data is stored.
	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Domain Administrator"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake LLC"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"1600 Amphitheatre Parkway"})
}

// TestParseWHOIS_XYZ_Noise validates that informational RDAP links located in the footer/disclaimer
// sections are not erroneously captured as the Registrar URL when the official field is empty.
func TestParseWHOIS_XYZ_Noise(t *testing.T) {
	rawWHOIS := `Domain Name: FAKE.XYZ
Registrar: Fake Registrar, Inc.
Registrar IANA ID: 999
Registrar URL:
Updated Date: 2025-11-11T12:00:30.0Z
Name Server: NS1.FAKE.XYZ

>>> IMPORTANT INFORMATION ABOUT THE DEPLOYMENT OF RDAP: please visit
https://www.fake.registry/rdap <<<

The Whois and RDAP services are provided by Fake Registry.`

	got := parseWHOIS(rawWHOIS)

	// The 'Registrar URL' field in the domain header is explicitly empty.
	// The parser must not scavenge unrelated URLs from the footer or promotional text,
	// especially those containing trailing noise characters like '<<<'.
	assertEq(t, "RegistrarURL", got.RegistrarURL, "")

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Registrar, Inc."})
	assertEq(t, "IANAID", got.IANAID, "999")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-11-11T12:00:30.0Z")
}

// TestParseWHOIS_ICANN_Footer validates that ICANN-format footer and disclaimer
// text does not leak into structured metadata fields.
func TestParseWHOIS_ICANN_Footer(t *testing.T) {
	rawWHOIS := `   Domain Name: FAKE.COM
   Registry Domain ID: 12345_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.fakeregistrar.com
   Registrar URL: http://www.fakeregistrar.com
   Updated Date: 2019-09-09T15:39:04Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2028-09-14T04:00:00Z
   Registrar: FakeRegistrar Inc.
   Registrar IANA ID: 292
   Registrar Abuse Contact Email: abuse@fakeregistrar.com
   Registrar Abuse Contact Phone: +1.2085551234
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: NS1.FAKE.COM
   Name Server: NS2.FAKE.COM
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
	assertEq(t, "WhoisServer", got.WhoisServer, "whois.fakeregistrar.com")
	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://www.fakeregistrar.com")
	assertEq(t, "IANAID", got.IANAID, "292")
	assertEq(t, "DNSSEC", got.DNSSEC, "unsigned")

	// Registrar.Name must contain ONLY the actual registrar name, not disclaimer text.
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FakeRegistrar Inc."})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.com", "ns2.fake.com"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{
		"clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
		"serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited",
	})

	// Footer/disclaimer text must NEVER leak into contact fields.
	assertSlice(t, "Registrar.Organization", got.Registrar.Organization, nil)
	assertSlice(t, "Registrar.Address", got.Registrar.Address, nil)
	assertSlice(t, "Registrant.Name", got.Registrant.Name, nil)
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, nil)
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@fakeregistrar.com"})
	assertSlice(t, "Abuse.Phone", got.Abuse.Phone, []string{"+1.2085551234"})
}

// TestParseWHOIS_TW validates Taiwanese .tw WHOIS format (TWNIC).
func TestParseWHOIS_TW(t *testing.T) {
	rawWHOIS := `
Domain Name: fake.com.tw
   Domain Status: clientTransferProhibited
   Registrant:
      Fake Taiwan Corp.
      Fake Global Inc.
      admin@fake.com.tw
      TW

   Record expires on 2035-05-31 00:00:00 (UTC+8)
   Record created on 1985-07-04 00:00:00 (UTC+8)

   Domain servers in listed order:
      ns1.fake.com.tw      1.2.3.4
      ns2.fake.com.tw      5.6.7.8

Registration Service Provider: FAKEPROVIDER
Registration Service URL: http://registrar.fake.tw
Registrar Abuse Contact Email: abuse@fake.tw
`

	got := parseWHOIS(rawWHOIS)

	// TWNIC uses a distinct date prefix "Record created/expires on" followed by a timestamp and timezone, which requires specific pattern matching.
	assertEq(t, "CreationDate", got.CreationDate, "1985-07-04 00:00:00 (UTC+8)")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2035-05-31 00:00:00 (UTC+8)")

	// Nameservers are grouped under a "Domain servers in listed order" header and often include associated IP addresses (glue records) that must be filtered out.
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.fake.com.tw", "ns2.fake.com.tw"})

	// "Registration Service Provider" is the standard field name for the Registrar in the .tw registry.
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FAKEPROVIDER"})

	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://registrar.fake.tw")
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@fake.tw"})

	// The Registrant block uses positional indentation to provide the Name, Organization, Email, and Location, necessitating sequential classification.
	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Fake Taiwan Corp."})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Global Inc."})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"admin@fake.com.tw"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"TW"})
}

// TestParseWHOIS_WhoisServerHTTP_Noise validates that 'http://' or 'https://' prefixes are stripped
// from the WhoisServer field so it remains a valid hostname rather than a URL.
func TestParseWHOIS_WhoisServerHTTP_Noise(t *testing.T) {
	rawWHOIS := `
Domain Name: fake.org
Registry Domain ID: REDACTED
Registrar WHOIS Server: http://whois.fakeregistrar.com
Registrar URL: http://www.fakeregistrar.com
Updated Date: 2025-12-17T09:26:13Z
Creation Date: 2001-01-13T00:12:14Z
Registry Expiry Date: 2027-01-13T00:12:14Z
Registrar: FakeRegistrar Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abuse@fakeregistrar.com
Registrar Abuse Contact Phone: +1.2083895740
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Name Server: ns0.fake.org
DNSSEC: unsigned
URL of the ICANN Whois Inaccuracy Complaint Form: https://icann.org/wicf/
>>> Last update of WHOIS database: 2026-04-07T14:44:13Z <<<

For more information on Whois status codes, please visit https://icann.org/epp
`
	got := parseWHOIS(rawWHOIS)

	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://www.fakeregistrar.com")

	// Ensure the "http://" prefix is stripped from WhoisServer!
	assertEq(t, "WhoisServer", got.WhoisServer, "whois.fakeregistrar.com")
}
