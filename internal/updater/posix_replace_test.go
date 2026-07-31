package updater

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type errorClosingReader struct {
	io.ReadCloser
}

func (e errorClosingReader) Close() error {
	if err := e.ReadCloser.Close(); err != nil {
		return err
	}
	return errors.New("mock gzip close error")
}

func TestReplacePOSIX(t *testing.T) {
	dummyContent := "content-posix"
	validArchive := createDummyTarGz(t, "ReconSR", dummyContent)
	invalidArchive := []byte("invalid-gzip-content")
	var b bytes.Buffer
	gw := gzip.NewWriter(&b)
	if _, err := gw.Write([]byte("not a tar")); err != nil {
		t.Fatalf("failed to write dummy content: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("failed to close gzip writer: %v", err)
	}
	validGzNoTar := b.Bytes()
	emptyArchive := createDummyTarGz(t, "not-ReconSR", dummyContent)

	origRename := osRename
	origRemove := osRemove
	origChmod := osChmod
	origCreateTemp := osCreateTemp
	origNewGzipReader := newGzipReader
	defer func() {
		osRename = origRename
		osRemove = origRemove
		osChmod = origChmod
		osCreateTemp = origCreateTemp
		newGzipReader = origNewGzipReader
	}()

	tests := []struct {
		body        io.Reader
		mockCreate  func(string, string) (*os.File, error)
		mockChmod   func(string, os.FileMode) error
		mockRename  func(string, string) error
		mockNewGzip func(io.Reader) (io.ReadCloser, error)
		name        string
		errContains string
		wantErr     bool
	}{
		{
			name:        "invalid_gzip",
			body:        bytes.NewBuffer(invalidArchive),
			wantErr:     true,
			errContains: "failed to initialize gzip reader",
		},
		{
			name:        "missing_reconsr_posix",
			body:        bytes.NewBuffer(emptyArchive),
			wantErr:     true,
			errContains: "ReconSR executable not found in archive",
		},
		{
			name:        "tar_reading_error",
			body:        bytes.NewBuffer(validGzNoTar),
			wantErr:     true,
			errContains: "failed to read tar archive",
		},
		{
			name: "create_temp_permission_denied",
			body: bytes.NewBuffer(validArchive),
			mockCreate: func(_, _ string) (*os.File, error) {
				return nil, os.ErrPermission
			},
			wantErr:     true,
			errContains: "elevated",
		},
		{
			name: "create_temp_other_error",
			body: bytes.NewBuffer(validArchive),
			mockCreate: func(_, _ string) (*os.File, error) {
				return nil, errors.New("other error")
			},
			wantErr:     true,
			errContains: "failed to create temporary file",
		},
		{
			name: "chmod_error",
			body: bytes.NewBuffer(createDummyTarGz(t, "ReconSR", dummyContent)),
			mockChmod: func(_ string, _ os.FileMode) error {
				return errors.New("chmod err")
			},
			wantErr:     true,
			errContains: "failed to make new binary executable",
		},
		{
			name: "rename_permission_denied_posix",
			body: bytes.NewBuffer(createDummyTarGz(t, "ReconSR", dummyContent)),
			mockRename: func(_, _ string) error {
				return os.ErrPermission
			},
			wantErr:     true,
			errContains: "elevated_2",
		},
		{
			name: "rename_other_error_posix",
			body: bytes.NewBuffer(createDummyTarGz(t, "ReconSR", dummyContent)),
			mockRename: func(_, _ string) error {
				return errors.New("rename err")
			},
			wantErr:     true,
			errContains: "failed to replace current executable",
		},
		{
			name:       "success_posix",
			body:       bytes.NewBuffer(createDummyTarGz(t, "ReconSR", dummyContent)),
			mockRename: func(_, _ string) error { return nil },
			mockChmod:  func(_ string, _ os.FileMode) error { return nil },
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockNewGzip != nil {
				newGzipReader = tt.mockNewGzip
			} else {
				newGzipReader = origNewGzipReader
			}
			if strings.HasPrefix(tt.errContains, "elevated") {
				tt.errContains = "permission denied"
			}
			if tt.mockCreate != nil {
				osCreateTemp = tt.mockCreate
			} else {
				osCreateTemp = func(_, pattern string) (*os.File, error) {
					return os.CreateTemp(t.TempDir(), pattern)
				}
			}
			if tt.mockChmod != nil {
				osChmod = tt.mockChmod
			} else {
				osChmod = func(_ string, _ os.FileMode) error { return nil }
			}
			if tt.mockRename != nil {
				osRename = tt.mockRename
			} else {
				osRename = func(_, _ string) error { return nil }
			}
			osRemove = func(string) error { return nil }

			err := replacePOSIX(tt.body, "/test/ReconSR")
			if (err != nil) != tt.wantErr {
				t.Errorf("replacePOSIX() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			}

			osCreateTemp = origCreateTemp
		})
	}
}

func TestReplacePOSIXFull(t *testing.T) {
	dummyContent := "content-full"
	validArchive := createDummyTarGz(t, "ReconSR", dummyContent)
	emptyArchive := createDummyTarGz(t, "not-ReconSR", dummyContent)

	origRename := osRename
	origRemove := osRemove
	origChmod := osChmod
	origNewGzipReader := newGzipReader
	defer func() {
		osRename = origRename
		osRemove = origRemove
		osChmod = origChmod
		newGzipReader = origNewGzipReader
	}()

	tests := []struct {
		body        io.Reader
		mockRename  func(string, string) error
		mockChmod   func(string, os.FileMode) error
		mockNewGzip func(io.Reader) (io.ReadCloser, error)
		mockRemove  func(string) error
		name        string
		errContains string
		wantErr     bool
	}{
		{
			name:        "invalid_gzip",
			body:        bytes.NewBufferString("invalid-gzip"),
			wantErr:     true,
			errContains: "failed to initialize gzip reader",
		},
		{
			name:        "missing_reconsr_full",
			body:        bytes.NewBuffer(emptyArchive),
			wantErr:     true,
			errContains: "ReconSR executable not found in archive",
		},
		{
			name: "chmod_error",
			body: bytes.NewBuffer(validArchive),
			mockChmod: func(_ string, _ os.FileMode) error {
				return errors.New("chmod err")
			},
			wantErr:     true,
			errContains: "failed to make new binary executable",
		},
		{
			name:      "rename_permission_denied_full",
			body:      bytes.NewBuffer(validArchive),
			mockChmod: func(_ string, _ os.FileMode) error { return nil },
			mockRename: func(_, _ string) error {
				return os.ErrPermission
			},
			wantErr:     true,
			errContains: "permission denied replacing executable",
		},
		{
			name:        "rename_other_error_full",
			body:        bytes.NewBuffer(validArchive),
			mockChmod:   func(string, os.FileMode) error { return nil },
			mockRename:  func(string, string) error { return errors.New("rename err") },
			mockRemove:  func(string) error { return errors.New("remove err") },
			wantErr:     true,
			errContains: "failed to replace current executable",
		},
		{
			name:       "success_full",
			body:       bytes.NewBuffer(validArchive),
			mockChmod:  func(_ string, _ os.FileMode) error { return nil },
			mockRename: func(_, _ string) error { return nil },
			wantErr:    false,
		},
		{
			name: "gzip_close_error",
			body: bytes.NewBuffer(validArchive),
			mockNewGzip: func(r io.Reader) (io.ReadCloser, error) {
				gzr, err := defaultNewGzipReader(r)
				if err != nil {
					return nil, err
				}
				return errorClosingReader{gzr}, nil
			},
			mockRename: func(_, _ string) error { return nil },
			mockChmod:  func(_ string, _ os.FileMode) error { return nil },
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockRemove != nil {
				osRemove = tt.mockRemove
			} else {
				osRemove = func(_ string) error { return nil }
			}
			if tt.mockNewGzip != nil {
				newGzipReader = tt.mockNewGzip
			} else {
				newGzipReader = origNewGzipReader
			}
			if tt.mockRename != nil {
				osRename = tt.mockRename
			} else {
				osRename = func(_, _ string) error { return nil }
			}
			if tt.mockChmod != nil {
				osChmod = tt.mockChmod
			} else {
				osChmod = func(_ string, _ os.FileMode) error { return nil }
			}

			tempDir := t.TempDir()

			err := replacePOSIX(tt.body, filepath.Join(tempDir, "ReconSR"))
			if (err != nil) != tt.wantErr {
				t.Errorf("replacePOSIX() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}

func TestPerformAtomicSwap_CopyError(t *testing.T) {
	origCreate := osCreateTemp
	origClose := tempFileClose
	defer func() {
		osCreateTemp = origCreate
		tempFileClose = origClose
	}()

	osCreateTemp = os.CreateTemp
	tempFileClose = func(*os.File) error {
		return errors.New("close err")
	}

	tempDir := t.TempDir()
	err := performAtomicSwap(errReader{}, filepath.Join(tempDir, "exec"))
	if err == nil || !strings.Contains(err.Error(), "failed to write new binary") {
		t.Errorf("expected write error, got %v", err)
	}
}

func TestPerformAtomicSwap_CloseError(t *testing.T) {
	origCreate := osCreateTemp
	origClose := tempFileClose
	defer func() {
		osCreateTemp = origCreate
		tempFileClose = origClose
	}()

	osCreateTemp = os.CreateTemp
	tempFileClose = func(*os.File) error {
		return errors.New("close err")
	}

	tempDir := t.TempDir()
	err := performAtomicSwap(bytes.NewBufferString("dummy"), filepath.Join(tempDir, "exec"))
	_ = err
}

func TestDefaultTempFileClose(t *testing.T) {
	tempFile, err := os.CreateTemp("", "ReconSR-test-close-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() {
		if rErr := os.Remove(tempFile.Name()); rErr != nil {
			t.Logf("failed to remove temp file: %v", rErr)
		}
	}()

	if cErr := tempFile.Close(); cErr != nil {
		t.Logf("temp file close: %v", cErr)
	}

	err = defaultTempFileClose(tempFile)
	if err == nil {
		t.Errorf("expected error closing an already closed file")
	}
}
