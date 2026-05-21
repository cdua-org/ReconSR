package whois

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseRDAP(t *testing.T) {
	rdapJSON := `
	{
		"events": [
			{"eventAction": "registration", "eventDate": "2000-01-01T12:00:00Z"},
			{"eventAction": "expiration", "eventDate": "2025-01-01T12:00:00Z"},
			{"eventAction": "last changed", "eventDate": "2023-01-01T12:00:00Z"}
		],
		"status": ["active"],
		"nameservers": [
			{"ldhName": "ns1.example.com"},
			{"ldhName": "ns2.example.com"}
		],
		"entities": [
			{
				"roles": ["registrar"],
				"vcardArray": [
					"vcard",
					[
						["fn", {}, "text", "Example Registrar"],
						["url", {}, "uri", "http://www.example.com"]
					]
				]
			},
			{
				"roles": ["registrant"],
				"vcardArray": [
					"vcard",
					[
						["fn", {}, "text", "Richard Roe"],
						["org", {}, "text", "Roe LLC"],
						["email", {}, "text", "john@doe.com"],
						["tel", {}, "text", "+1.5551234567"],
						["adr", {}, "text", "123 Main St"]
					]
				]
			}
		]
	}`

	var data map[string]any
	err := json.Unmarshal([]byte(rdapJSON), &data)
	if err != nil {
		t.Fatalf("Failed to unmarshal RDAP JSON: %v", err)
	}

	expected := Metadata{
		CreationDate:   "2000-01-01T12:00:00Z",
		ExpirationDate: "2025-01-01T12:00:00Z",
		UpdatedDate:    "2023-01-01T12:00:00Z",
		DomainStatus:   []string{"active"},
		NameServers:    []string{"ns1.example.com", "ns2.example.com"},
		Registrar: Contact{
			Name: []string{"Example Registrar"},
		},
		RegistrarURL: "http://www.example.com",
		Registrant: Contact{
			Name:         []string{"Richard Roe"},
			Organization: []string{"Roe LLC"},
			Email:        []string{"john@doe.com"},
			Phone:        []string{"+1.5551234567"},
			Address:      []string{"123 Main St"},
		},
	}

	got := parseRDAP(data)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("parseRDAP() mismatch\nGot:  %+v\nWant: %+v", got, expected)
	}
}
