package dnsutils

import (
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const unknownGateway = "<unknown>"

// IPSECKEYRecord represents a parsed IPSECKEY DNS record.
type IPSECKEYRecord struct {
	Precedence      string
	GatewayType     string
	Algorithm       string
	Gateway         string
	PublicKeyBase64 string
	Formatted       string
}

type wireDomainDecodeResult struct {
	domain     string
	nextOffset int
	ok         bool
}

func decodeWireDomain(data []byte, offset int) wireDomainDecodeResult {
	if offset >= len(data) {
		return wireDomainDecodeResult{}
	}

	labels := make([]string, 0, 4)
	for offset < len(data) {
		labelLen := int(data[offset])
		offset++

		if labelLen == 0 {
			if len(labels) == 0 {
				return wireDomainDecodeResult{domain: ".", nextOffset: offset, ok: true}
			}
			return wireDomainDecodeResult{domain: strings.Join(labels, "."), nextOffset: offset, ok: true}
		}

		if labelLen&0xC0 != 0 || labelLen > 63 || offset+labelLen > len(data) {
			return wireDomainDecodeResult{}
		}

		labels = append(labels, string(data[offset:offset+labelLen]))
		offset += labelLen
	}

	return wireDomainDecodeResult{}
}

// ParseIPSECKEY parses either an RFC3597 wire-format string or a plain-text IPSECKEY record.
func ParseIPSECKEY(raw string) *IPSECKEYRecord {
	data, ok := DecodeWireFormat(raw, 3)
	if !ok {
		parts := strings.Fields(raw)
		if len(parts) >= 5 {
			return &IPSECKEYRecord{
				Precedence:      parts[0],
				GatewayType:     parts[1],
				Algorithm:       parts[2],
				Gateway:         parts[3],
				PublicKeyBase64: strings.Join(parts[4:], ""),
				Formatted:       strings.Join(parts, " "),
			}
		}
		return nil
	}

	precedence := data[0]
	gwType := data[1]
	alg := data[2]

	var gw string
	var pubKeyBytes []byte

	offset := 3
	switch gwType {
	case 0:
		gw = "."
		pubKeyBytes = data[offset:]
	case 1:
		if len(data) >= offset+4 {
			gw = net.IP(data[offset : offset+4]).String()
			pubKeyBytes = data[offset+4:]
		} else {
			gw = unknownGateway
			pubKeyBytes = data[offset:]
		}
	case 2:
		if len(data) >= offset+16 {
			gw = net.IP(data[offset : offset+16]).String()
			pubKeyBytes = data[offset+16:]
		} else {
			gw = unknownGateway
			pubKeyBytes = data[offset:]
		}
	case 3:
		decodedDomain := decodeWireDomain(data, offset)
		if decodedDomain.ok {
			gw = decodedDomain.domain
			pubKeyBytes = data[decodedDomain.nextOffset:]
		} else {
			gw = unknownGateway
			pubKeyBytes = data[offset:]
		}
	default:
		gw = unknownGateway
		pubKeyBytes = data[offset:]
	}

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	return &IPSECKEYRecord{
		Precedence:      strconv.Itoa(int(precedence)),
		GatewayType:     strconv.Itoa(int(gwType)),
		Algorithm:       strconv.Itoa(int(alg)),
		Gateway:         gw,
		PublicKeyBase64: pubKeyBase64,
		Formatted:       fmt.Sprintf("%d %d %d %s %s", precedence, gwType, alg, gw, pubKeyBase64),
	}
}
