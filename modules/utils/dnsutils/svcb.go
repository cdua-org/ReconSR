package dnsutils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var svcbParamName = map[uint16]string{
	0: "mandatory",
	1: "alpn",
	2: "no-default-alpn",
	3: "port",
	4: "ipv4hint",
	5: "ech",
	6: "ipv6hint",
}

// ParseSVCB tries to parse the SVCB/HTTPS record from wire format, then falls back to presentation format.
func ParseSVCB(raw string) (priority uint16, target string, params map[string]string, ok bool) {
	if priority, target, params, ok = ParseSVCBWire(raw); ok {
		return priority, target, params, true
	}
	return ParseSVCBPresentation(raw)
}

// ParseSVCBPresentation parses an SVCB record in presentation format (e.g., "1 . alpn=h3,h2 ipv4hint=...").
func ParseSVCBPresentation(raw string) (priority uint16, target string, params map[string]string, ok bool) {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for _, r := range raw {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case r == ' ' && !inQuotes:
			if current.Len() > 0 {
				parts = append(parts, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	if len(parts) < 2 {
		return 0, "", nil, false
	}

	prio64, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, "", nil, false
	}
	priority = uint16(prio64)
	target = strings.TrimSuffix(parts[1], ".")
	if target == "" {
		target = "."
	}

	params = make(map[string]string)
	for _, part := range parts[2:] {
		if k, v, found := strings.Cut(part, "="); found {
			params[k] = v
		} else {
			params[part] = ""
		}
	}

	return priority, target, params, true
}

// ParseSVCBWire parses raw SVCB/HTTPS wire data into a priority, target, and map of parameters.
func ParseSVCBWire(raw string) (priority uint16, target string, params map[string]string, ok bool) {
	data, decoded := DecodeWireFormat(raw, 3)
	if !decoded {
		return 0, "", nil, false
	}

	priority = binary.BigEndian.Uint16(data[0:2])
	offset := 2

	var labels []string
	for offset < len(data) {
		labelLen := int(data[offset])
		offset++
		if labelLen == 0 {
			break
		}
		if offset+labelLen > len(data) {
			return 0, "", nil, false
		}
		labels = append(labels, string(data[offset:offset+labelLen]))
		offset += labelLen
	}

	if len(labels) > 0 {
		target = strings.Join(labels, ".")
	} else {
		target = "."
	}

	params = make(map[string]string)
	for offset+4 <= len(data) {
		key := binary.BigEndian.Uint16(data[offset : offset+2])
		valLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if offset+valLen > len(data) {
			break
		}
		valBytes := data[offset : offset+valLen]
		offset += valLen

		paramName, known := svcbParamName[key]
		if !known {
			paramName = fmt.Sprintf("key%d", key)
		}

		params[paramName] = decodeSVCBParam(key, valBytes)
	}

	return priority, target, params, true
}

func decodeSVCBParam(key uint16, val []byte) string {
	switch key {
	case 1:
		var protos []string
		i := 0
		for i < len(val) {
			pLen := int(val[i])
			i++
			if i+pLen > len(val) {
				break
			}
			protos = append(protos, string(val[i:i+pLen]))
			i += pLen
		}
		return strings.Join(protos, ",")

	case 3:
		if len(val) == 2 {
			return strconv.FormatUint(uint64(binary.BigEndian.Uint16(val)), 10)
		}

	case 4:
		var addrs []string
		for i := 0; i+4 <= len(val); i += 4 {
			addrs = append(addrs, net.IP(val[i:i+4]).String())
		}
		return strings.Join(addrs, ",")

	case 5:
		return hex.EncodeToString(val)

	case 6:
		var addrs []string
		for i := 0; i+16 <= len(val); i += 16 {
			addrs = append(addrs, net.IP(val[i:i+16]).String())
		}
		return strings.Join(addrs, ",")
	}

	return hex.EncodeToString(val)
}
