package dnsutils

import (
	"bytes"
	"testing"
)

func TestDecodeWireFormat(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantData   []byte
		minDataLen int
		wantOK     bool
	}{
		{
			name:       "valid hex with spaces",
			raw:        "\\# 4 00 01 02 03",
			minDataLen: 4,
			wantData:   []byte{0x00, 0x01, 0x02, 0x03},
			wantOK:     true,
		},
		{
			name:       "valid hex without spaces",
			raw:        "\\# 4 00010203",
			minDataLen: 4,
			wantData:   []byte{0x00, 0x01, 0x02, 0x03},
			wantOK:     true,
		},
		{
			name:       "min data len enforcement",
			raw:        "\\# 2 0001",
			minDataLen: 4,
			wantData:   nil,
			wantOK:     false,
		},
		{
			name:       "zero min data len",
			raw:        "\\# 1 FF",
			minDataLen: 0,
			wantData:   []byte{0xFF},
			wantOK:     true,
		},
		{
			name:       "not rfc3597 format",
			raw:        "ns1.example.com",
			minDataLen: 0,
			wantData:   nil,
			wantOK:     false,
		},
		{
			name:       "malformed hex",
			raw:        "\\# 4 ZZZZ",
			minDataLen: 0,
			wantData:   nil,
			wantOK:     false,
		},
		{
			name:       "empty hex after prefix",
			raw:        "\\# 0",
			minDataLen: 0,
			wantData:   nil,
			wantOK:     false,
		},
		{
			name:       "missing length field",
			raw:        "\\#",
			minDataLen: 0,
			wantData:   nil,
			wantOK:     false,
		},
		{
			name:       "empty hex spaces only",
			raw:        "\\# 0   ",
			minDataLen: 0,
			wantData:   nil,
			wantOK:     false,
		},
		{
			name:       "sshfp typical valid",
			raw:        "\\# 22 01 01 abcdef0123456789abcdef0123456789abcdef01",
			minDataLen: 3,
			wantData: func() []byte {
				fp := []byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01}
				b := make([]byte, 0, 2+len(fp))
				b = append(b, 0x01, 0x01)
				b = append(b, fp...)
				return b
			}(),
			wantOK: true,
		},
		{
			name:       "prefix without space",
			raw:        "\\#4 00010203",
			minDataLen: 0,
			wantData:   nil,
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotData, gotOK := DecodeWireFormat(tt.raw, tt.minDataLen)
			if gotOK != tt.wantOK {
				t.Errorf("ok = %v, want %v", gotOK, tt.wantOK)
			}
			if !bytes.Equal(gotData, tt.wantData) {
				t.Errorf("data = %v, want %v", gotData, tt.wantData)
			}
		})
	}
}
