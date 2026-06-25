package dns

import (
	"context"
	"errors"
	"net"
	"slices"
	"testing"

	"cdua-org/ReconSR/modules/utils/constants"
	"cdua-org/ReconSR/modules/utils/modutil"
)

func TestGetDomainKeyDataEmpty(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	execution := getDomainKeyData(context.Background(), "empty.example", modutil.NewLocalIDGenerator())

	if execution.Error != nil {
		t.Fatalf("unexpected error: %v", *execution.Error)
	}

	if len(execution.Results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(execution.Results))
	}
}

func TestGetDomainKeyData(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		_, err := fallback(context.Background(), net.DefaultResolver)
		if err == nil {
			t.Log("fallback unexpectedly succeeded")
		}

		return []string{
			"\"v=DKIM1; k=rsa; p=MIGfMA0GCSq...\"",
		}, []byte("mocked raw data"), nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDomainKeyData(context.Background(), "test.example", modutil.NewLocalIDGenerator())

	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res.Results))
	}
	if res.RawData == "" {
		t.Error("expected RawData to be set")
	}
}

func TestGetDomainKeyData_Error(t *testing.T) {
	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, _ func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		return nil, nil, errors.New("mock domainkey error")
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDomainKeyData(context.Background(), "error.example", modutil.NewLocalIDGenerator())

	if res.Error == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetDomainKeyData_FallbackSuccess(t *testing.T) {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer func() {
		if closeErr := pc.Close(); closeErr != nil {
			t.Logf("failed to close packet conn: %v", closeErr)
		}
	}()

	go func() {
		buf := make([]byte, 512)
		n, addr, readErr := pc.ReadFrom(buf)
		if readErr != nil {
			return
		}
		if n < 12 {
			return
		}

		resp := make([]byte, 0, 512)
		resp = append(resp, buf[0:12]...)

		resp[2], resp[3] = 0x85, 0x80
		resp[6], resp[7] = 0x00, 0x01

		qEnd := 12
		for qEnd < n && buf[qEnd] != 0 {
			qEnd += int(buf[qEnd]) + 1
		}
		qEnd += 5
		if qEnd <= n {
			resp = append(resp, buf[12:qEnd]...)
		}

		resp = append(resp, 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x0E, 0x10)

		const mockDomainKeyData = "v=DKIM1; k=rsa; p=MIGfMA0GCSq...Success"
		dataLen := uint(len(mockDomainKeyData)) + 1

		resp = append(resp, byte(dataLen>>8), byte(dataLen&0xFF), byte(dataLen-1))
		resp = append(resp, []byte(mockDomainKeyData)...)

		if _, writeErr := pc.WriteTo(resp, addr); writeErr != nil {
			return
		}
	}()

	oldResolve := resolveRecordFunc
	resolveRecordFunc = func(_ context.Context, _ string, _ int, fallback func(context.Context, *net.Resolver) ([]string, error)) ([]string, []byte, error) {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "udp", pc.LocalAddr().String())
			},
		}

		txts, err := fallback(context.Background(), r)
		if err != nil {
			t.Errorf("fallback failed: %v", err)
		}
		const mockDomainKeyData = "v=DKIM1; k=rsa; p=MIGfMA0GCSq...Success"
		if len(txts) == 0 || txts[0] != mockDomainKeyData {
			t.Errorf("unexpected fallback result: %v", txts)
		}
		return []string{mockDomainKeyData}, []byte("mocked"), nil
	}
	defer func() { resolveRecordFunc = oldResolve }()

	res := getDomainKeyData(context.Background(), "success.example", modutil.NewLocalIDGenerator())
	if res.Error != nil {
		t.Fatalf("unexpected error: %v", *res.Error)
	}
}

func TestDomainKeyCapabilities(t *testing.T) {
	mod := New()
	caps, err := mod.Capabilities()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !slices.Contains(caps.Functions, constants.FuncGetDomainKey) {
		t.Error("expected get_domainkey in capabilities")
	}
}
