package whois

import (
	"regexp"
	"testing"
)

func TestParseWHOIS_EdgeCases(t *testing.T) {
	rawWHOIS := `
Domain Status: FakeStatus
state: FakeState
contact: billing
Billing Name: Bob Billing
address: 123 Billing St
                Apt 4B
  US

abuse:
abuse-email: abuse@edge.example.com
name: Abuse Guy
address: 123 Abuse St
                Apt 5B

Registrar:
address: 123 Reg St
                Apt Reg

unknown contact:
                Apt X

Registrant:
address: 123 Reg St
                Apt 1
state: FakeState2
Administrative Contact:
address: 123 Admin St
                Apt 2
Technical Contact:
address: 123 Tech St
                Apt 3

Registrant Street: 123 Reg St
                Apt 1
Admin Street: 123 Admin St
                Apt 2
Tech Street: 123 Tech St
                Apt 3
Billing Street: 123 Billing St
                Apt 4

Registrant Fax: +1.234
`
	got := parseWHOIS(rawWHOIS)

	assertSlice(t, "Billing.Name", got.Billing.Name, []string{"Bob Billing"})
	assertSlice(t, "Abuse.Email", got.Abuse.Email, []string{"abuse@edge.example.com"})
	assertSlice(t, "Registrant.Fax", got.Registrant.Fax, []string{"+1.234"})

	applyContactMatch(&got.Registrant, "unknown_field", "unknown_", "value")

	applyAustrianMatch(&got, "at_changed", "20230801")
	applyAustrianMatch(&got, "at_nserver", "ns3.fake.at")
	applyAustrianMatch(&got, "at_tech_c", "FAKETECH2")
	applyAustrianMatch(&got, "at_admin_c", "FAKEADMIN2")
	applyAustrianMatch(&got, "at_unknown", "value")

	applyDomainMatch(&got, whoisFieldCNRegistrant, "CN Org")
	applyDomainMatch(&got, whoisFieldCNRegistrantEmail, "cn@cn.example.com")
	classifyIndentedLine(&got, whoisRoleNameServers, "ns1.deadcode.example.com", 0)
	classifyIndentedLine(&got, "unknown_role", "Data", 0)
	applyTWMatch(&got, "tw_url", "http://edge.test.example")
	applyKRMatch(&got, whoisFieldKRRegZip, "12345")
}

func TestParseWHOIS_StateCoverage(_ *testing.T) {
	origPatterns := whoisPatterns
	defer func() { whoisPatterns = origPatterns }()

	whoisPatterns = map[string]*regexp.Regexp{
		whoisFieldStatus: origPatterns[whoisFieldStatus],
	}
	parseWHOIS("Domain Status: FakeStatus\ncontact: billing\nstate: FakeState\n")

	whoisPatterns = map[string]*regexp.Regexp{
		whoisFieldRPSLAddr: origPatterns[whoisFieldRPSLAddr],
	}
	parseWHOIS("contact: billing\nstate: FakeState\n")

	whoisPatterns = origPatterns
	parseWHOIS("state:FakeState\n")
	parseWHOIS("state: N/A\n")
}
