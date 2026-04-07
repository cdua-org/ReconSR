package dns

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

// svcbParamName maps SVCB SvcParamKey numbers to human-readable names (RFC 9460).
var svcbParamName = map[uint16]string{
	0: "mandatory",
	1: "alpn",
	2: "no-default-alpn",
	3: "port",
	4: "ipv4hint",
	5: "ech",
	6: "ipv6hint",
}

// parseSVCBWire decodes RFC 3597 wire format for SVCB/HTTPS records (RFC 9460).
// Wire: 2b SvcPriority + compressed TargetName + SvcParams (key-value TLVs).
func parseSVCBWire(raw string) (priority uint16, target string, params map[string]string, ok bool) {
	if !strings.HasPrefix(raw, "\\# ") {
		return 0, "", nil, false
	}

	fields := strings.SplitN(raw, " ", 3)
	if len(fields) < 3 {
		return 0, "", nil, false
	}

	hexStr := strings.ReplaceAll(fields[2], " ", "")
	data, err := hex.DecodeString(hexStr)
	if err != nil || len(data) < 3 {
		return 0, "", nil, false
	}

	priority = binary.BigEndian.Uint16(data[0:2])
	offset := 2

	// Decode DNS name (label-length encoding, no compression pointers in SVCB)
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

// decodeSVCBParam converts raw SvcParam value bytes into human-readable form.
func decodeSVCBParam(key uint16, val []byte) string {
	switch key {
	case 1: // alpn — list of length-prefixed protocol identifiers
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

	case 3: // port
		if len(val) == 2 {
			return strconv.FormatUint(uint64(binary.BigEndian.Uint16(val)), 10)
		}

	case 4: // ipv4hint — concatenated 4-byte IPv4 addresses
		var addrs []string
		for i := 0; i+4 <= len(val); i += 4 {
			addrs = append(addrs, net.IP(val[i:i+4]).String())
		}
		return strings.Join(addrs, ",")

	case 5: // ech — base64 or just hex for now
		return hex.EncodeToString(val)

	case 6: // ipv6hint — concatenated 16-byte IPv6 addresses
		var addrs []string
		for i := 0; i+16 <= len(val); i += 16 {
			addrs = append(addrs, net.IP(val[i:i+16]).String())
		}
		return strings.Join(addrs, ",")
	}

	return hex.EncodeToString(val)
}

func getSVCBData(target string) schema.ModuleExecution {
	execution := schema.ModuleExecution{
		Function: "get_svcb",
		Results:  []schema.ModuleResult{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Query both SVCB (64) and HTTPS (65) in parallel
	type queryResult struct {
		records []string
		qtype   string
		raw     []byte
	}

	ch := make(chan queryResult, 2)

	for _, qt := range []struct {
		name string
		code int
	}{
		{"SVCB", 64},
		{"HTTPS", 65},
	} {
		go func(code int, name string) {
			recs, raw, err := resolver.ResolveRecord(ctx, target, code, nil)
			if err != nil {
				ch <- queryResult{qtype: name}
				return
			}
			ch <- queryResult{records: recs, qtype: name, raw: raw}
		}(qt.code, qt.name)
	}

	var rawParts []string

	for range 2 {
		res := <-ch

		if len(res.raw) > 0 {
			rawParts = append(rawParts, string(res.raw))
		}

		for _, rec := range res.records {
			priority, svcTarget, params, decoded := parseSVCBWire(rec)

			if !decoded {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   rec,
					Context: res.qtype + " Record",
				})
				continue
			}

			// Human-readable summary
			var sb strings.Builder
			fmt.Fprintf(&sb, "priority=%d target=%s", priority, svcTarget)
			for k, v := range params {
				fmt.Fprintf(&sb, " %s=%s", k, v)
			}

			execution.Results = append(execution.Results, schema.ModuleResult{
				Type:    "string",
				Value:   sb.String(),
				Context: res.qtype + " Record",
			})

			// Extract IPs from hints
			if v, ok := params["ipv4hint"]; ok {
				for ip := range strings.SplitSeq(v, ",") {
					execution.Results = append(execution.Results, schema.ModuleResult{
						Type:    "ipv4",
						Value:   ip,
						Context: res.qtype + " IPv4 Hint",
					})
				}
			}
			if v, ok := params["ipv6hint"]; ok {
				for ip := range strings.SplitSeq(v, ",") {
					execution.Results = append(execution.Results, schema.ModuleResult{
						Type:    "ipv6",
						Value:   ip,
						Context: res.qtype + " IPv6 Hint",
					})
				}
			}

			// Extract ALPN protocols
			if v, ok := params["alpn"]; ok {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   v,
					Context: res.qtype + " ALPN Protocols",
				})
			}

			// Extract ECH config
			if v, ok := params["ech"]; ok {
				execution.Results = append(execution.Results, schema.ModuleResult{
					Type:    "string",
					Value:   v,
					Context: res.qtype + " ECH Config",
				})
			}
		}
	}

	if len(rawParts) > 0 {
		execution.RawData = strings.Join(rawParts, "\n")
	}

	return execution
}
