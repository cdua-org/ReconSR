package dns

import (
	"context"
	"fmt"
	"math"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/dnsutils"
	"cdua-org/ReconSR/modules/utils/modutil"
	"cdua-org/ReconSR/modules/utils/resolver"
	"cdua-org/ReconSR/schema"
)

func parseLOC(raw string) string {
	data, ok := dnsutils.DecodeWireFormat(raw, 16)
	if !ok {
		return raw
	}
	if len(data) != 16 {
		return raw
	}

	if data[0] != 0 {
		return raw
	}

	decodeSize := func(b byte) string {
		m := b >> 4
		e := b & 0x0F
		valCm := float64(m) * math.Pow10(int(e))
		return fmt.Sprintf("%.2fm", valCm/100.0)
	}

	decodeCoord := func(val uint32, pos, neg string) string {
		offset := uint32(2147483648)
		var dir string
		var diff uint32
		if val >= offset {
			dir = pos
			diff = val - offset
		} else {
			dir = neg
			diff = offset - val
		}

		secThousandths := diff % 1000
		totalSecs := diff / 1000
		sec := totalSecs % 60
		totalMins := totalSecs / 60
		mins := totalMins % 60
		deg := totalMins / 60

		return fmt.Sprintf("%d %d %.3f %s", deg, mins, float64(sec)+float64(secThousandths)/1000.0, dir)
	}

	size := decodeSize(data[1])
	horiz := decodeSize(data[2])
	vert := decodeSize(data[3])

	latVal := uint32(data[4])<<24 | uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
	lonVal := uint32(data[8])<<24 | uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11])
	altVal := uint32(data[12])<<24 | uint32(data[13])<<16 | uint32(data[14])<<8 | uint32(data[15])

	lat := decodeCoord(latVal, "N", "S")
	lon := decodeCoord(lonVal, "E", "W")
	alt := (float64(altVal) - 10000000.0) / 100.0

	return fmt.Sprintf("%s %s %.2fm %s %s %s", lat, lon, alt, size, horiz, vert)
}

func getLOCData(ctx context.Context, target string) schema.ModuleExecution {
	exec := modutil.NewExecution(constants.FuncGetLOC)

	log.Printf("get_loc target=%q", target)

	queryCtx, cancel := context.WithTimeout(ctx, resolver.DNSQueryTimeout)
	defer cancel()

	records, raw, err := resolver.ResolveRecord(queryCtx, target, 29, nil)
	if err != nil {
		log.Printf("get_loc error: %v", err)
		modutil.SetError(&exec, "loc lookup failed: %v", err)
		return exec
	}

	modutil.SetRawFromBytes(&exec, raw)

	log.Printf("get_loc target=%q records=%d", target, len(records))

	for _, rec := range records {
		exec.Results = append(exec.Results, schema.ModuleResult{
			Type:     constants.TypeLOC,
			Category: constants.CategoryProperty,
			Value:    parseLOC(rec),
			Context:  "Geographic Location",
		})
	}

	return exec
}
