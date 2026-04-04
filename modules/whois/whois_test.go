package whois

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSafeString(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "string",
			input:    "hello",
			expected: "hello",
		},
		{
			name:     "list of strings",
			input:    []any{"hello", "world"},
			expected: "hello, world",
		},
		{
			name:     "list with empty strings",
			input:    []any{"hello", "", "world"},
			expected: "hello, world",
		},
		{
			name:     "list with non-strings",
			input:    []any{"hello", 123, "world"},
			expected: "hello, world",
		},
		{
			name:     "invalid type",
			input:    123,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeString(tt.input); got != tt.expected {
				t.Errorf("safeString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseWHOIS(t *testing.T) {
	rawWHOIS := `
Domain Name: EXAMPLE.COM
Registry Domain ID: 123456789_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.example.com
Registrar URL: http://www.example.com
Updated Date: 2023-01-01T12:00:00Z
Creation Date: 2000-01-01T12:00:00Z
Registry Expiry Date: 2025-01-01T12:00:00Z
Registrar: Example Registrar, Inc.
Registrar IANA ID: 9999
Registrar Abuse Contact Email: abuse@example.com
Registrar Abuse Contact Phone: +1.5555555555
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
DNSSEC: unsigned

Registrant Name: John Doe
Registrant Organization: Doe Inc
Registrant Street: 123 Main St
Registrant City: Anytown
Registrant State/Province: CA
Registrant Postal Code: 12345
Registrant Country: US
Registrant Phone: +1.5551234567
Registrant Email: john@doe.com

Admin Name: Jane Smith
Admin Organization: Smith LLC
Admin Street: 456 Elm St
Admin Phone: +1.5559876543
Admin Email: jane@smith.com

Tech Name: Tech Guy
Tech Organization: Tech Co
Tech Phone: +1.5551112222
Tech Email: tech@tech.com
`

	expected := Metadata{
		RegistrarURL:   "http://www.example.com",
		WhoisServer:    "whois.example.com",
		IANAID:         "9999",
		DNSSEC:         "unsigned",
		CreationDate:   "2000-01-01T12:00:00Z",
		UpdatedDate:    "2023-01-01T12:00:00Z",
		ExpirationDate: "2025-01-01T12:00:00Z",
		NameServers:    []string{"ns1.example.com", "ns2.example.com"},
		DomainStatus:   []string{"clientTransferProhibited https://icann.org/epp#clientTransferProhibited"},
		Registrar: Contact{
			Name: "Example Registrar, Inc.",
		},
		Registrant: Contact{
			Name:         "John Doe",
			Organization: "Doe Inc",
			Email:        "john@doe.com",
			Address:      "123 Main St, Anytown, CA, 12345, US",
			Phone:        "+1.5551234567",
		},
		Admin: Contact{
			Name:         "Jane Smith",
			Organization: "Smith LLC",
			Email:        "jane@smith.com",
			Address:      "456 Elm St",
			Phone:        "+1.5559876543",
		},
		Tech: Contact{
			Name:         "Tech Guy",
			Organization: "Tech Co",
			Email:        "tech@tech.com",
			Phone:        "+1.5551112222",
		},
		Abuse: Contact{
			Email: "abuse@example.com",
			Phone: "+1.5555555555",
		},
	}

	got := parseWHOIS(rawWHOIS)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("parseWHOIS() mismatch\nGot:  %+v\nWant: %+v", got, expected)
	}
}

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
						["fn", {}, "text", "John Doe"],
						["org", {}, "text", "Doe Inc"],
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
			Name: "Example Registrar",
		},
		RegistrarURL: "http://www.example.com",
		Registrant: Contact{
			Name:         "John Doe",
			Organization: "Doe Inc",
			Email:        "john@doe.com",
			Phone:        "+1.5551234567",
			Address:      "123 Main St",
		},
	}

	got := parseRDAP(data)
	if !reflect.DeepEqual(got, expected) {
		t.Errorf("parseRDAP() mismatch\nGot:  %+v\nWant: %+v", got, expected)
	}
}
