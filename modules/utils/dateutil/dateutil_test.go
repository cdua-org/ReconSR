package dateutil

import (
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/schema"
)

func TestNormalizeDay(t *testing.T) {
	tests := []struct {
		name  string
		raw   string
		want  string
		valid bool
	}{
		{name: "iso microseconds", raw: "2026-06-06T05:10:57.536000", want: "2026-06-06", valid: true},
		{name: "date only", raw: "2026-06-07", want: "2026-06-07", valid: true},
		{name: "rfc3339", raw: "2026-06-09T10:15:30Z", want: "2026-06-09", valid: true},
		{name: "spaced format", raw: "2026-06-08 23:59:58", want: "2026-06-08", valid: true},
		{name: "slash format", raw: "2026/06/11 12:13:14", want: "2026-06-11", valid: true},
		{name: "european format", raw: "12.06.2026 09:08:07", want: "2026-06-12", valid: true},
		{name: "invalid", raw: "not-a-date", want: "", valid: false},
		{name: "empty string", raw: "   ", want: "", valid: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeDay(tt.raw)
			if ok != tt.valid {
				t.Fatalf("NormalizeDay(%q) valid=%v, want %v", tt.raw, ok, tt.valid)
			}
			if got != tt.want {
				t.Fatalf("NormalizeDay(%q)=%q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCollectorKeepsLatestDayPerKey(t *testing.T) {
	collector := NewCollector()
	firstSource := &schema.EntityRef{Type: constants.TypeIPv4, Value: "198.51.100.25", LocalID: 11}
	secondSource := &schema.EntityRef{Type: constants.TypeIPv4, Value: "198.51.100.25", LocalID: 22}

	collector.Add(constants.TypeIPv4+"\x00198.51.100.25", firstSource, "2026-05-02T12:30:00.000000")
	collector.Add(constants.TypeIPv4+"\x00198.51.100.25", secondSource, "2026-06-06T05:10:57.536000")

	items := collector.Items()
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Day != "2026-06-06" {
		t.Fatalf("expected latest day 2026-06-06, got %q", items[0].Day)
	}
	if items[0].Source == nil {
		t.Fatal("expected source to be preserved")
	}
	if items[0].Source.LocalID != 11 {
		t.Fatalf("expected first source LocalID 11, got %d", items[0].Source.LocalID)
	}
}

func TestCollectorUsesCallerDefinedKeys(t *testing.T) {
	collector := NewCollector()
	collector.Add("mx\x0010 mx.example.net", &schema.EntityRef{Type: "mx", Value: "10 mx.example.net", LocalID: 1}, "2026-06-01T09:00:00.000000")
	collector.Add("soa\x00ns1.example.net. hostmaster.example.net. 1 2 3 4 5", &schema.EntityRef{Type: "soa", Value: "ns1.example.net. hostmaster.example.net. 1 2 3 4 5", LocalID: 2}, "2026-06-02T09:00:00.000000")

	items := collector.Items()
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if items[0].Day != "2026-06-01" {
		t.Fatalf("expected first day 2026-06-01, got %q", items[0].Day)
	}
	if items[1].Day != "2026-06-02" {
		t.Fatalf("expected second day 2026-06-02, got %q", items[1].Day)
	}
}

func TestCollectorSkipsInvalidInputs(t *testing.T) {
	collector := NewCollector()
	collector.Add("", &schema.EntityRef{Type: constants.TypeIPv4, Value: "198.51.100.99"}, "2026-06-06T05:10:57.536000")
	collector.Add(constants.TypeIPv4+"\x00198.51.100.99", &schema.EntityRef{Type: constants.TypeIPv4, Value: "198.51.100.99"}, "bad-date")
	collector.Add("valid", nil, "2026-06-10")

	items := collector.Items()
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Day != "2026-06-10" {
		t.Fatalf("expected normalized day 2026-06-10, got %q", items[0].Day)
	}
	if items[0].Source != nil {
		t.Fatalf("expected nil source to stay nil, got %+v", items[0].Source)
	}
}

func TestCollectorUpdatesSourceWhenFirstEntryWasNil(t *testing.T) {
	collector := NewCollector()
	collector.Add("target", nil, "2026-06-01")
	collector.Add("target", &schema.EntityRef{Type: constants.TypeMX, Value: "10 mx.example.org", LocalID: 7}, "2026-06-02")

	items := collector.Items()
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}
	if items[0].Source == nil {
		t.Fatal("expected source to be updated from nil")
	}
	if items[0].Source.Type != constants.TypeMX || items[0].Source.Value != "10 mx.example.org" || items[0].Source.LocalID != 7 {
		t.Fatalf("unexpected updated source: %+v", items[0].Source)
	}
	if items[0].Day != "2026-06-02" {
		t.Fatalf("expected latest day 2026-06-02, got %q", items[0].Day)
	}
}

func TestCollectorNilAndEmptyBehaviors(t *testing.T) {
	var nilCollector *Collector
	nilCollector.Add("ignored", &schema.EntityRef{Type: constants.TypeSOA, Value: "ns1.example.org."}, "2026-06-03")
	if items := nilCollector.Items(); items != nil {
		t.Fatalf("expected nil items for nil collector, got %+v", items)
	}

	emptyCollector := NewCollector()
	if items := emptyCollector.Items(); items != nil {
		t.Fatalf("expected nil items for empty collector, got %+v", items)
	}
}
