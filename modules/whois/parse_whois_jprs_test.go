package whois

import (
	"testing"
)

func TestParseWHOIS_JPRS1(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/jprs_1.txt")
	got := parseWHOIS(rawWHOIS)

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Corporation"})
	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"AB12345JP"})
	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"CD67890JP", "EF11111JP"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.jpns-alpha.example.net", "ns2.jpns-alpha.example.net"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"Connected (2028/06/30)"})
	assertEq(t, "CreationDate", got.CreationDate, "2015/07/01")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026/03/15 10:30:00 (JST)")
}

func TestParseWHOIS_JPRS2(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/jprs_2.txt")
	got := parseWHOIS(rawWHOIS)

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Store Inc."})
	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Proxy Solutions Ltd. Fake"})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"proxy@fakeprivacy.example"})
	assertSlice(t, "Registrant.Phone", got.Registrant.Phone, []string{"+81.312345678", "+81.312345679"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address,
		[]string{"100-0001", "Fake Tower 5F, 1-2-3 Marunouchi", "Chiyoda-ku, Tokyo"})

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.jpns-beta.example.org", "ns2.jpns-beta.example.org"})
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"Active", "DomainTransferLocked"})
	assertEq(t, "CreationDate", got.CreationDate, "2005/04/10")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2028/04/10")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2026/02/20 09:15:00 (JST)")
}
