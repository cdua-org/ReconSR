// file: parse_whois_krnic_test.go

package whois

import (
	"testing"
)

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
