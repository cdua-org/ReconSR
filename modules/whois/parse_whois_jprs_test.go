// file: parse_whois_jprs_test.go

package whois

import (
	"testing"
)

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
