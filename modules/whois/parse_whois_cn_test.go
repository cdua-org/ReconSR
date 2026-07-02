package whois

import "testing"

func TestParseWHOIS_CN(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/cn.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "2003-03-17 12:20:05")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "2029-03-17 12:48:36")
	assertEq(t, "DNSSEC", got.DNSSEC, "unsigned")

	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"clientDeleteProhibited", "serverUpdateProhibited"})
	assertSlice(t, "Registrar.Name", got.Registrar.Name, []string{"Fake Beijing Registrar Co. Ltd"})

	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Mock Registry Ltd"})
	assertSlice(t, "Registrant.Email", got.Registrant.Email, []string{"fake@cn.test.example"})

	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.cn.test.example", "ns2.cn.test.example", "ns3.cn.test.example", "ns4.cn.test.example"})
}
