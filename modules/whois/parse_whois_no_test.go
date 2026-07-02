package whois

import "testing"

func TestParseWHOIS_NO(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/no.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1999-11-15")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "2025-10-18")
	assertEq(t, "DNSSEC", got.DNSSEC, "Signed")

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"REG99-NORID"})

	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"NH1234R-NORID"})

	assertSlice(t, "NameServers", got.NameServers, []string{"A1111H-NORID", "A2222H-NORID"})
}
