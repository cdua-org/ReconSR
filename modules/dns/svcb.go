package dns

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"

	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
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

func parseSVCBWire(raw string) (priority uint16, target string, params map[string]string, ok bool) {
	data, decoded := dnsutils.DecodeWireFormat(raw, 3)
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

func getSVCBData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution("get_svcb")
	log.Printf("get_svcb target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

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
			recs, raw, err := resolver.ResolveRecord(queryCtx, target, code, nil)
			if err != nil {
				log.Printf("get_svcb %s error: %v", name, err)
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
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     "svcb",
					Category: "property",
					Value:    rec,
					Context:  res.qtype + " Record",
				})
				continue
			}

			var sb strings.Builder
			fmt.Fprintf(&sb, "priority=%d target=%s", priority, svcTarget)
			for k, v := range params {
				fmt.Fprintf(&sb, " %s=%s", k, v)
			}

			exec.Results = append(exec.Results, schema.ModuleResult{
				Type:     "svcb",
				Category: "property",
				Value:    sb.String(),
				Context:  res.qtype + " Record",
			})

			if v, ok := params["ipv4hint"]; ok {
				for ip := range strings.SplitSeq(v, ",") {
					exec.Results = append(exec.Results, schema.ModuleResult{
						Type:     "ipv4",
						Category: "node",
						Value:    ip,
						Context:  res.qtype + " IPv4 Hint",
					})
				}
			}
			if v, ok := params["ipv6hint"]; ok {
				for ip := range strings.SplitSeq(v, ",") {
					exec.Results = append(exec.Results, schema.ModuleResult{
						Type:     "ipv6",
						Category: "node",
						Value:    ip,
						Context:  res.qtype + " IPv6 Hint",
					})
				}
			}

			if v, ok := params["alpn"]; ok {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     "svcb",
					Category: "property",
					Value:    v,
					Context:  res.qtype + " ALPN Protocols",
				})
			}

			if v, ok := params["ech"]; ok {
				exec.Results = append(exec.Results, schema.ModuleResult{
					Type:     "svcb",
					Category: "property",
					Value:    v,
					Context:  res.qtype + " ECH Config",
				})
			}
		}
	}

	if len(rawParts) > 0 {
		exec.RawData = strings.Join(rawParts, "\n")
	}

	log.Printf("get_svcb target=%q results=%d", target, len(exec.Results))
	return exec
}
