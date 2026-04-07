// file: parse_whois_krnic_test.go

package whois

import (
	"testing"
)

// TestParseWHOIS_KRNIC validates Korean KRNIC format with Host Name
// name servers and Administrative Contact(AC) fields.
func TestParseWHOIS_KRNIC(t *testing.T) {
	rawWHOIS := `
# KOREAN(UTF8)

도메인이름                  : fakecompany.co.kr
등록인                      : 주식회사 페이크
등록인 주소                 : 서울특별시 강남구 가짜로 99
등록인 우편번호             : 06100
책임자                      : 주식회사 페이크
책임자 전자우편             : domain@fakecompany.example
책임자 전화번호             : 02-1234-5678
등록일                      : 2000. 03. 15.
최근 정보 변경일            : 2024. 06. 20.
사용 종료일                 : 2027. 03. 15.
정보공개여부                : Y
등록대행자                  : (주)페이크에이전트(http://fakeagent.example)
DNSSEC                      : 미서명
등록정보 보호               : clientTransferProhibited
등록정보 보호               : clientUpdateProhibited

1차 네임서버 정보
   호스트이름               : ns1.fakecompany.example
   IP 주소                  : 192.0.2.1

2차 네임서버 정보
   호스트이름               : ns2.fakecompany.example
   IP 주소                  : 198.51.100.1
   호스트이름               : ns3.fakecompany.example
   IP 주소                  : 203.0.113.1

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
Domain Status               : clientUpdateProhibited

Primary Name Server
   Host Name                : ns1.fakecompany.example
   IP Address               : 192.0.2.1

Secondary Name Server
   Host Name                : ns2.fakecompany.example
   IP Address               : 198.51.100.1
   Host Name                : ns3.fakecompany.example
   IP Address               : 203.0.113.1
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
	assertSlice(t, "DomainStatus", got.DomainStatus, []string{"clientTransferProhibited", "clientUpdateProhibited"})

	assertSlice(t, "NameServers", got.NameServers,
		[]string{"ns1.fakecompany.example", "ns2.fakecompany.example", "ns3.fakecompany.example"})
}
