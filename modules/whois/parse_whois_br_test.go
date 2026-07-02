package whois

import "testing"

func TestParseWHOIS_BR(t *testing.T) {
	rawWHOIS := loadFixture(t, "testdata/br.txt")

	got := parseWHOIS(rawWHOIS)

	assertEq(t, "CreationDate", got.CreationDate, "19960424 #7137")
	assertEq(t, "UpdatedDate", got.UpdatedDate, "20240827")
	assertEq(t, "ExpirationDate", got.ExpirationDate, "20340424")
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"published"})
	assertSlice(t, "NameServers", got.NameServers, []string{"ns1.br.test.example"})
	assertSlice(t, "Registrant.Organization", got.Registrant.Organization, []string{"Fake S.A.", "12.345.678/0001-99"})
	assertSlice(t, "Admin.Name", got.Admin.Name, []string{"Admin Contact"})
	assertSlice(t, "Admin.Email", got.Admin.Email, []string{"admin@br.test.example"})
	assertSlice(t, "Tech.Name", got.Tech.Name, []string{"Tech Contact"})
	assertSlice(t, "Tech.Email", got.Tech.Email, []string{"tech@br.test.example"})
}
