package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type updateTestCase struct {
	client         *http.Client
	mockExecutable func() (string, error)
	mockEvalSym    func(string) (string, error)
	mockRename     func(string, string) error
	mockRemove     func(string) error
	mockChmod      func(string, os.FileMode) error
	mockWriteFile  func(string, []byte, os.FileMode) error
	mockCreate     func(string) (*os.File, error)
	name           string
	version        string
	errContains    string
	mockOS         string
	wantErr        bool
}

func TestUpdate(t *testing.T) {
	dummyContent := "new-binary-content"
	validArchivePOSIX := createDummyTarGz(t, "ReconSR", dummyContent)
	validArchiveWin := createDummyZip(t, "ReconSR.exe", dummyContent)

	digestPOSIX := sha256.Sum256(validArchivePOSIX)
	digestWin := sha256.Sum256(validArchiveWin)
	digestPOSIXHex := "sha256:" + hex.EncodeToString(digestPOSIX[:])
	digestWinHex := "sha256:" + hex.EncodeToString(digestWin[:])

	validJSON := fmt.Sprintf(`{
		"tag_name": "v1.1.0",
		"assets": [
			{"name": "ReconSR-linux-amd64.tar.gz", "browser_download_url": "http://dl/linux-amd64", "digest": "%s"},
			{"name": "ReconSR-linux-arm64.tar.gz", "browser_download_url": "http://dl/linux-arm64", "digest": "%s"},
			{"name": "ReconSR-macos-intel.tar.gz", "browser_download_url": "http://dl/macos-intel", "digest": "%s"},
			{"name": "ReconSR-macos-apple-silicon.tar.gz", "browser_download_url": "http://dl/macos-silicon", "digest": "%s"},
			{"name": "ReconSR-windows-x64.zip", "browser_download_url": "http://dl/windows-x64", "digest": "%s"},
			{"name": "ReconSR-windows-arm64.zip", "browser_download_url": "http://dl/windows-arm64", "digest": "%s"}
		]
	}`, digestPOSIXHex, digestPOSIXHex, digestPOSIXHex, digestPOSIXHex, digestWinHex, digestWinHex)

	platformKey := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	assetName := SupportedPlatforms[platformKey]

	successClient := newMockClient(func(req *http.Request) (*http.Response, error) {
		if strings.Contains(req.URL.String(), "releases/latest") {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(validJSON)),
			}, nil
		}
		if osGOOS == osWindows {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(validArchiveWin))}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(validArchivePOSIX))}, nil
	})

	tests := []updateTestCase{
		{
			name:        "dev_version",
			version:     "dev",
			client:      nil,
			errContains: "",
			wantErr:     false,
		},
		{
			name:    "already_up_to_date",
			version: "v1.1.0",
			client:  successClient,
			wantErr: false,
		},
		{
			name: "api_network_error",
			client: newMockClient(func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("network error")
			}),
			wantErr:     true,
			errContains: "network error fetching release",
		},
		{
			name: "api_bad_status",
			client: newMockClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
			}),
			wantErr:     true,
			errContains: "unexpected status from GitHub API",
		},
		{
			name: "invalid_json",
			client: newMockClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString("{bad"))}, nil
			}),
			wantErr:     true,
			errContains: "failed to parse GitHub API response",
		},
		{
			name: "missing_asset",
			client: newMockClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(`{"tag_name":"v1.1.0","assets":[]}`))}, nil
			}),
			wantErr:     true,
			errContains: "not found in the latest release",
		},
		{
			name: "download_network_error",
			client: newMockClient(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "releases") {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(validJSON))}, nil
				}
				return nil, errors.New("dl err")
			}),
			wantErr:     true,
			errContains: "network error downloading asset",
		},
		{
			name: "download_bad_status",
			client: newMockClient(func(req *http.Request) (*http.Response, error) {
				if strings.Contains(req.URL.String(), "releases") {
					return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(validJSON))}, nil
				}
				return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
			}),
			wantErr:     true,
			errContains: "unexpected status downloading asset",
		},
		{
			name:   "os_executable_error",
			client: successClient,
			mockExecutable: func() (string, error) {
				return "", errors.New("exec error")
			},
			wantErr:     true,
			errContains: "failed to determine executable path",
		},
		{
			name:   "eval_symlinks_error",
			client: successClient,
			mockExecutable: func() (string, error) {
				return "/bin/ReconSR", nil
			},
			mockEvalSym: func(_ string) (string, error) {
				return "", errors.New("symlink error")
			},
			wantErr:     true,
			errContains: "failed to evaluate symlinks",
		},
		{
			name: "missing_digest",
			client: newMockClient(func(_ *http.Request) (*http.Response, error) {
				body := fmt.Sprintf(`{"tag_name":"v1.1.0","assets":[{"name":%q,"browser_download_url":"http://dl"}]}`, assetName)
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(body))}, nil
			}),
			wantErr:     true,
			errContains: "not found via GitHub API",
		},
		{
			name:        "unsupported_platform",
			client:      successClient,
			wantErr:     true,
			errContains: "unsupported platform",
		},
		{
			name:   "update_success_windows",
			client: successClient,
			mockOS: osWindows,
			mockExecutable: func() (string, error) {
				return filepath.Join(t.TempDir(), "ReconSR.exe"), nil
			},
			mockChmod:  func(_ string, _ os.FileMode) error { return nil },
			mockRename: func(_, _ string) error { return nil },
			mockRemove: func(_ string) error { return nil },
			wantErr:    false,
		},
		{
			name:   "update_success_posix",
			client: successClient,
			mockOS: "linux",
			mockExecutable: func() (string, error) {
				return filepath.Join(t.TempDir(), "ReconSR"), nil
			},
			mockChmod:  func(_ string, _ os.FileMode) error { return nil },
			mockRename: func(_, _ string) error { return nil },
			mockRemove: func(_ string) error { return nil },
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.version == "" {
				tt.version = "v1.0.0"
			}
			runTestUpdate(t, &tt)
		})
	}
}

func runTestUpdate(t *testing.T, tt *updateTestCase) {
	origExec := osExecutable
	origEval := filepathEvalSymlinks
	origRename := osRename
	origRemove := osRemove
	origChmod := osChmod
	origCreate := osCreate
	origWrite := osWriteFile

	defer func() {
		osExecutable = origExec
		filepathEvalSymlinks = origEval
		osRename = origRename
		osRemove = origRemove
		osChmod = origChmod
		osCreate = origCreate
		osWriteFile = origWrite
	}()

	if tt.mockExecutable != nil {
		osExecutable = tt.mockExecutable
	}
	if tt.mockEvalSym != nil {
		filepathEvalSymlinks = tt.mockEvalSym
	} else {
		filepathEvalSymlinks = func(s string) (string, error) { return s, nil }
	}
	if tt.mockOS != "" {
		osGOOS = tt.mockOS
	} else {
		osGOOS = runtime.GOOS
	}
	if tt.mockRename != nil {
		osRename = tt.mockRename
	}
	if tt.mockRemove != nil {
		osRemove = tt.mockRemove
	}
	if tt.mockChmod != nil {
		osChmod = tt.mockChmod
	}
	if tt.mockCreate != nil {
		osCreate = tt.mockCreate
	}
	if tt.mockWriteFile != nil {
		osWriteFile = tt.mockWriteFile
	}

	if tt.name == "unsupported_platform" {
		origPlat := SupportedPlatforms
		SupportedPlatforms = map[string]string{}
		defer func() { SupportedPlatforms = origPlat }()
	}

	var ctx context.Context
	var cancel context.CancelFunc
	if tt.name == "api_network_error" {
		ctx = context.Background()
	} else {
		ctx, cancel = context.WithCancel(context.Background())
		defer cancel()
	}

	err := Update(ctx, tt.client, tt.version)
	if (err != nil) != tt.wantErr {
		t.Errorf("Update() error = %v, wantErr %v", err, tt.wantErr)
	}
	if err != nil && tt.errContains != "" {
		if !strings.Contains(err.Error(), tt.errContains) {
			t.Errorf("expected error to contain %q, got %q", tt.errContains, err.Error())
		}
	}
}

func TestUpdate_RequestErrors(t *testing.T) {
	client := newMockClient(func(_ *http.Request) (*http.Response, error) {
		return nil, errors.New("mock network error")
	})
	err := Update(context.TODO(), client, "v1.0.0")
	if err == nil || !strings.Contains(err.Error(), "network error fetching release") {
		t.Errorf("expected network error, got %v", err)
	}
}

func TestFetchLatestRelease_RequestError(t *testing.T) {
	origURL := endpointUpdate
	defer func() { endpointUpdate = origURL }()
	endpointUpdate = "://invalid-url"

	_, err := fetchLatestRelease(context.Background(), http.DefaultClient)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to create request") {
		t.Fatalf("expected 'failed to create request', got %v", err)
	}
}

func TestFetchLatestRelease_BodyCloseError(t *testing.T) {
	client := newMockClient(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body: mockBodyCloseError{
				Reader: strings.NewReader(`{"tag_name":"v1.1.0","assets":[]}`),
			},
		}, nil
	})

	_, err := fetchLatestRelease(context.Background(), client)
	if err != nil {
		t.Fatalf("expected no error (body close error is suppressed), got: %v", err)
	}
}

func TestDownloadAndVerifyAsset(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		url            string
		expectedDigest string
		client         *http.Client
		errContains    string
	}{
		{
			name:        "request_error",
			url:         "://invalid-url",
			client:      http.DefaultClient,
			errContains: "failed to create download request",
		},
		{
			name:           "read_body_error",
			url:            "http://example.com/asset",
			expectedDigest: "sha256:dummy",
			client: newMockClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(errReader{}),
				}, nil
			}),
			errContains: "failed to read downloaded asset",
		},
		{
			name:           "checksum_mismatch",
			url:            "http://example.net/asset",
			expectedDigest: "sha256:wronghash",
			client: newMockClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("content")),
				}, nil
			}),
			errContains: "checksum mismatch",
		},
		{
			name: "body_close_error",
			url:  "http://example.org/asset",
			expectedDigest: func() string {
				h := sha256.Sum256([]byte("content"))
				return "sha256:" + hex.EncodeToString(h[:])
			}(),
			client: newMockClient(func(_ *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       mockBodyCloseError{Reader: strings.NewReader("content")},
				}, nil
			}),
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := downloadAndVerifyAsset(ctx, tt.client, tt.url, tt.expectedDigest)
			if tt.errContains != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("expected error containing %q, got %v", tt.errContains, err)
				}
			} else if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}
