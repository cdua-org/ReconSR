package whois

import "testing"

func TestParseWHOIS_TW(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/tw.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "1985-07-04 00:00:00 (UTC+8)")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2035-05-31 00:00:00 (UTC+8)")

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.tw.test.example", "ns2.tw.test.example"})

	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"FAKEPROVIDER"})

	assertEq(t, "RegistrarURL", got.RegistrarURL, "http://registrar.tw2.test.example")
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@tw2.test.example"})

	assertSlice(t, "Registrant.Name", got.Registrant.Name, []string{"Fake Taiwan Corp."})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake Global Inc."})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"admin@tw.test.example"})
	assertSlice(t, "Registrant.Address", got.Registrant.Address, []string{"TW"})
}
