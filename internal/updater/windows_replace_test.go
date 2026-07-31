package updater

import (
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

func TestReplaceWindows(t *testing.T) {
	dummyContent := "content-win"
	validArchive := createDummyZip(t, "ReconSR.exe", dummyContent)
	emptyArchive := createDummyZip(t, "not-ReconSR.exe", dummyContent)

	origRename := osRename
	origRemove := osRemove
	origWrite := osWriteFile
	origZipOpen := zipOpen
	defer func() {
		osRename = origRename
		osRemove = origRemove
		osWriteFile = origWrite
		zipOpen = origZipOpen
	}()

	tests := []struct {
		body        io.Reader
		mockRename  func(string, string) error
		mockWrite   func(string, []byte, os.FileMode) error
		mockZipOpen func(*zip.File) (io.ReadCloser, error)
		name        string
		errContains string
		wantErr     bool
	}{
		{
			name:        "read_body_error",
			body:        errReader{},
			wantErr:     true,
			errContains: "failed to read zip body",
		},
		{
			name:        "invalid_zip",
			body:        bytes.NewBufferString("invalid-zip"),
			wantErr:     true,
			errContains: "failed to initialize zip reader",
		},
		{
			name:        "missing_reconsr_win",
			body:        bytes.NewBuffer(emptyArchive),
			wantErr:     true,
			errContains: "ReconSR.exe not found in archive",
		},
		{
			name: "rename_permission_denied_win",
			body: bytes.NewBuffer(validArchive),
			mockRename: func(_, _ string) error {
				return os.ErrPermission
			},
			wantErr:     true,
			errContains: "permission denied. Please run with Administrator privileges",
		},
		{
			name: "rename_other_error_win",
			body: bytes.NewBuffer(validArchive),
			mockRename: func(_, _ string) error {
				return errors.New("rename err")
			},
			wantErr:     true,
			errContains: "failed to rename current executable",
		},
		{
			name:       "write_permission_denied",
			body:       bytes.NewBuffer(validArchive),
			mockRename: func(_, _ string) error { return nil },
			mockWrite: func(_ string, _ []byte, _ os.FileMode) error {
				return os.ErrPermission
			},
			wantErr:     true,
			errContains: "permission denied while writing new binary",
		},
		{
			name:       "write_other_error",
			body:       bytes.NewBuffer(validArchive),
			mockRename: func(_, _ string) error { return nil },
			mockWrite: func(_ string, _ []byte, _ os.FileMode) error {
				return errors.New("write err")
			},
			wantErr:     true,
			errContains: "failed to write new binary",
		},
		{
			name:       "success_win",
			body:       bytes.NewBuffer(validArchive),
			mockRename: func(_, _ string) error { return nil },
			mockWrite:  func(_ string, _ []byte, _ os.FileMode) error { return nil },
			wantErr:    false,
		},
		{
			name: "open_error",
			body: bytes.NewBuffer(validArchive),
			mockZipOpen: func(_ *zip.File) (io.ReadCloser, error) {
				return nil, errors.New("mock open err")
			},
			wantErr:     true,
			errContains: "failed to open ReconSR.exe in zip",
		},
		{
			name: "close_error",
			body: bytes.NewBuffer(validArchive),
			mockZipOpen: func(f *zip.File) (io.ReadCloser, error) {
				rc, err := f.Open()
				if err != nil {
					return nil, err
				}
				return errorClosingReader{rc}, nil
			},
			mockRename: func(_, _ string) error { return nil },
			mockWrite:  func(_ string, _ []byte, _ os.FileMode) error { return nil },
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osRemove = func(string) error { return nil }
			if tt.mockRename != nil {
				osRename = tt.mockRename
			} else {
				osRename = origRename
			}
			if tt.mockWrite != nil {
				osWriteFile = tt.mockWrite
			} else {
				osWriteFile = origWrite
			}
			if tt.mockZipOpen != nil {
				zipOpen = tt.mockZipOpen
			} else {
				zipOpen = origZipOpen
			}

			err := replaceWindows(tt.body, "/test/ReconSR.exe")
			if (err != nil) != tt.wantErr {
				t.Errorf("replaceWindows() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errContains != "" {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			}
		})
	}
}

func TestCleanupWindowsOldFiles(t *testing.T) {
	origGOOS := osGOOS
	osGOOS = osWindows
	origExec := osExecutable
	origEval := filepathEvalSymlinks
	origRemove := osRemove

	defer func() {
		osGOOS = origGOOS
		osExecutable = origExec
		filepathEvalSymlinks = origEval
		osRemove = origRemove
	}()

	tests := []struct {
		mockExecutable   func() (string, error)
		mockFilepathEval func(string) (string, error)
		mockRemove       func(string) error
		name             string
	}{
		{
			name: "exec_error",
			mockExecutable: func() (string, error) {
				return "", errors.New("exec error")
			},
		},
		{
			name: "symlink_error",
			mockExecutable: func() (string, error) {
				return "/test1/ReconSR.exe", nil
			},
			mockFilepathEval: func(_ string) (string, error) {
				return "", errors.New("symlink error")
			},
		},
		{
			name: "success",
			mockExecutable: func() (string, error) {
				return "/test2/ReconSR.exe", nil
			},
			mockFilepathEval: func(s string) (string, error) {
				return s, nil
			},
			mockRemove: func(_ string) error {
				return nil
			},
		},
		{
			name: "remove_error",
			mockExecutable: func() (string, error) {
				return "/test3/ReconSR.exe", nil
			},
			mockFilepathEval: func(s string) (string, error) {
				return s, nil
			},
			mockRemove: func(_ string) error {
				return errors.New("remove error")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(_ *testing.T) {
			if tt.mockExecutable != nil {
				osExecutable = tt.mockExecutable
			}
			if tt.mockFilepathEval != nil {
				filepathEvalSymlinks = tt.mockFilepathEval
			}
			if tt.mockRemove != nil {
				osRemove = tt.mockRemove
			}
			CleanupWindowsOldFiles()
		})
	}

	t.Run("not_windows", func(_ *testing.T) {
		osGOOS = "linux"
		CleanupWindowsOldFiles()
	})
}

func TestPerformWindowsReplace_RenameBack(t *testing.T) {
	orig := osWriteFile
	origRename := osRename
	defer func() {
		osWriteFile = orig
		osRename = origRename
	}()
	osWriteFile = func(_ string, _ []byte, _ os.FileMode) error {
		return errors.New("write error")
	}
	osRename = func(old, _ string) error {
		if strings.HasSuffix(old, ".old") {
			return errors.New("rename back err")
		}
		return nil
	}

	err := performWindowsReplace(bytes.NewBufferString("test"), "/tmp/exec")
	if err == nil || !strings.Contains(err.Error(), "failed to write new binary") {
		t.Errorf("expected write error, got %v", err)
	}
}

func TestPerformWindowsReplace_ReadError(t *testing.T) {
	origRename := osRename
	defer func() {
		osRename = origRename
	}()
	osRename = func(old, _ string) error {
		if strings.HasSuffix(old, ".old") {
			return errors.New("rename back err")
		}
		return nil
	}

	err := performWindowsReplace(errReader{}, "/tmp/exec")
	if err == nil || !strings.Contains(err.Error(), "failed to read new binary from archive") {
		t.Errorf("expected read error, got %v", err)
	}
}

func TestDefaultZipOpen(t *testing.T) {
	validArchive := createDummyZip(t, "ReconSR.exe", "content")

	invalidArchive := make([]byte, len(validArchive))
	copy(invalidArchive, validArchive)

	idx := bytes.Index(invalidArchive, []byte{0x50, 0x4b, 0x03, 0x04})
	if idx != -1 {
		invalidArchive[idx+8] = 99
		invalidArchive[idx+9] = 0
	}

	idx = bytes.Index(invalidArchive, []byte{0x50, 0x4b, 0x01, 0x02})
	if idx != -1 {
		invalidArchive[idx+10] = 99
		invalidArchive[idx+11] = 0
	}

	zrInvalid, err := zip.NewReader(bytes.NewReader(invalidArchive), int64(len(invalidArchive)))
	if err != nil {
		t.Fatalf("failed to initialize zip reader: %v", err)
	}
	if len(zrInvalid.File) == 0 {
		t.Fatalf("no files in dummy zip")
	}
	_, err = defaultZipOpen(zrInvalid.File[0])
	if err == nil {
		t.Errorf("expected error from defaultZipOpen with unsupported method, got nil")
	} else if !strings.Contains(err.Error(), "zip open error") {
		t.Errorf("expected 'zip open error', got: %v", err)
	}

	zrValid, err := zip.NewReader(bytes.NewReader(validArchive), int64(len(validArchive)))
	if err != nil {
		t.Fatalf("failed to initialize zip reader: %v", err)
	}
	rc, err := defaultZipOpen(zrValid.File[0])
	if err != nil {
		t.Fatalf("unexpected error from defaultZipOpen: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Logf("close error: %v", err)
	}
}
