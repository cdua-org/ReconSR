// Package updater provides the functionality to update the application in place.
package updater

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"cdua-org/ReconSR/internal/cli/spinner"
)

var endpointUpdate = "https://api.github.com/repos/cdua-org/ReconSR/releases/latest"

const osWindows = "windows"

func defaultNewGzipReader(r io.Reader) (io.ReadCloser, error) {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip init error: %w", err)
	}
	return gzr, nil
}

func defaultZipOpen(f *zip.File) (io.ReadCloser, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("zip open error: %w", err)
	}
	return rc, nil
}

func defaultTempFileClose(f *os.File) error {
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	return nil
}

// SupportedPlatforms maps OS/Arch combinations to asset filenames.
var SupportedPlatforms = map[string]string{
	"linux/amd64":   "ReconSR-linux-amd64.tar.gz",
	"linux/arm64":   "ReconSR-linux-arm64.tar.gz",
	"darwin/amd64":  "ReconSR-macos-intel.tar.gz",
	"darwin/arm64":  "ReconSR-macos-apple-silicon.tar.gz",
	"windows/amd64": "ReconSR-windows-x64.zip",
	"windows/arm64": "ReconSR-windows-arm64.zip",
}

var (
	osExecutable         = os.Executable
	filepathEvalSymlinks = filepath.EvalSymlinks
	osRemove             = os.Remove
	osRename             = os.Rename
	osChmod              = os.Chmod
	osCreate             = os.Create
	osCreateTemp         = os.CreateTemp
	osWriteFile          = os.WriteFile
	osGOOS               = runtime.GOOS
	newGzipReader        = defaultNewGzipReader
	zipOpen              = defaultZipOpen
	tempFileClose        = defaultTempFileClose
)

type releaseInfo struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Digest             string `json:"digest"`
	} `json:"assets"`
}

func fetchLatestRelease(ctx context.Context, client *http.Client) (*releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpointUpdate, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network error fetching release: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			_ = err
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status from GitHub API: %d", resp.StatusCode)
	}

	var release releaseInfo
	if decodeErr := json.NewDecoder(resp.Body).Decode(&release); decodeErr != nil {
		return nil, fmt.Errorf("failed to parse GitHub API response: %w", decodeErr)
	}
	return &release, nil
}

// Update downloads and applies the latest update.
func Update(ctx context.Context, client *http.Client, currentVersion string) error {
	if currentVersion == "dev" {
		fmt.Fprintln(os.Stderr, "Error: update not available for development builds")
		return nil
	}

	platformKey := fmt.Sprintf("%s/%s", osGOOS, runtime.GOARCH)
	assetName, supported := SupportedPlatforms[platformKey]
	if !supported {
		return fmt.Errorf("unsupported platform: %s", platformKey)
	}

	fetchSpinner := spinner.Start(ctx, "Fetching latest version from GitHub...", nil, 0)
	release, err := fetchLatestRelease(ctx, client)
	fetchSpinner()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Latest version: %s\n", release.TagName)
	fmt.Fprintf(os.Stderr, "Current version: %s\n", currentVersion)

	if release.TagName == currentVersion {
		fmt.Fprintf(os.Stderr, "Versions match. No update required.\n")
		return nil
	}

	var downloadURL string
	var expectedDigest string
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			downloadURL = asset.BrowserDownloadURL
			expectedDigest = asset.Digest
			break
		}
	}

	if downloadURL == "" {
		return fmt.Errorf("asset %s not found in the latest release", assetName)
	}

	if expectedDigest == "" {
		return fmt.Errorf("checksum for %s not found via GitHub API", assetName)
	}

	label := "Downloading " + release.TagName
	stopSpinner := spinner.Start(ctx, label, nil, 0)

	bodyBytes, err := downloadAndVerifyAsset(ctx, client, downloadURL, expectedDigest)
	if err != nil {
		stopSpinner()
		return err
	}

	execPath, err := osExecutable()
	if err != nil {
		stopSpinner()
		return fmt.Errorf("failed to determine executable path: %w", err)
	}
	execPath, err = filepathEvalSymlinks(execPath)
	if err != nil {
		stopSpinner()
		return fmt.Errorf("failed to evaluate symlinks for executable: %w", err)
	}

	if osGOOS == osWindows {
		err = replaceWindows(bytes.NewReader(bodyBytes), execPath)
	} else {
		err = replacePOSIX(bytes.NewReader(bodyBytes), execPath)
	}

	stopSpinner()

	if err == nil {
		fmt.Fprintf(os.Stderr, "Successfully updated to %s!\n", release.TagName)
	}
	return err
}

func downloadAndVerifyAsset(ctx context.Context, client *http.Client, url, expectedDigest string) ([]byte, error) {
	dlReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	dlResp, err := client.Do(dlReq)
	if err != nil {
		return nil, fmt.Errorf("network error downloading asset: %w", err)
	}
	defer func() {
		if cErr := dlResp.Body.Close(); cErr != nil {
			_ = cErr
		}
	}()

	if dlResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status downloading asset: %d", dlResp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(dlResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read downloaded asset: %w", err)
	}

	hash := sha256.Sum256(bodyBytes)
	actualHash := hex.EncodeToString(hash[:])
	expectedHashStr := strings.TrimPrefix(expectedDigest, "sha256:")
	if actualHash != expectedHashStr {
		return nil, fmt.Errorf("downloaded file checksum mismatch (expected: %s, got: %s)", expectedHashStr, actualHash)
	}
	return bodyBytes, nil
}

func replacePOSIX(body io.Reader, execPath string) error {
	gzr, err := newGzipReader(body)
	if err != nil {
		return fmt.Errorf("failed to initialize gzip reader: %w", err)
	}
	defer func() {
		if err := gzr.Close(); err != nil {
			_ = err
		}
	}()

	tr := tar.NewReader(gzr)
	for {
		hdr, tarErr := tr.Next()
		if errors.Is(tarErr, io.EOF) {
			break
		}
		if tarErr != nil {
			return fmt.Errorf("failed to read tar archive: %w", tarErr)
		}

		if filepath.Base(hdr.Name) != "ReconSR" {
			continue
		}

		return performAtomicSwap(tr, execPath)
	}

	return errors.New("ReconSR executable not found in archive")
}

func replaceWindows(body io.Reader, execPath string) error {
	data, err := io.ReadAll(body)
	if err != nil {
		return fmt.Errorf("failed to read zip body: %w", err)
	}

	zr, err := zip.NewReader(strings.NewReader(string(data)), int64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to initialize zip reader: %w", err)
	}

	for _, file := range zr.File {
		if filepath.Base(file.Name) != "ReconSR.exe" {
			continue
		}

		rc, zErr := zipOpen(file)
		if zErr != nil {
			return fmt.Errorf("failed to open ReconSR.exe in zip: %w", zErr)
		}

		err = performWindowsReplace(rc, execPath)
		if closeErr := rc.Close(); closeErr != nil {
			_ = closeErr
		}
		return err
	}

	return errors.New("ReconSR.exe not found in archive")
}

func performAtomicSwap(src io.Reader, execPath string) error {
	dir := filepath.Dir(execPath)
	tempFile, err := osCreateTemp(dir, ".ReconSR-new-*")
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return errors.New("permission denied. Please run with elevated privileges (e.g., sudo ReconSR update)")
		}
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	tempName := tempFile.Name()
	defer func() {
		if err := osRemove(tempName); err != nil {
			_ = err
		}
	}()

	if _, copyErr := io.Copy(tempFile, src); copyErr != nil {
		if err := tempFileClose(tempFile); err != nil {
			_ = err
		}
		return fmt.Errorf("failed to write new binary: %w", copyErr)
	}
	if err := tempFileClose(tempFile); err != nil {
		_ = err
	}

	if chmodErr := osChmod(tempName, 0o755); chmodErr != nil {
		return fmt.Errorf("failed to make new binary executable: %w", chmodErr)
	}

	if renameErr := osRename(tempName, execPath); renameErr != nil {
		if errors.Is(renameErr, os.ErrPermission) {
			return errors.New("permission denied replacing executable. Please run with elevated privileges (e.g., sudo ReconSR update)")
		}
		return fmt.Errorf("failed to replace current executable: %w", renameErr)
	}

	return nil
}

func performWindowsReplace(src io.Reader, execPath string) error {
	oldPath := execPath + ".old"

	if err := osRemove(oldPath); err != nil {
		_ = err
	}

	if renameErr := osRename(execPath, oldPath); renameErr != nil {
		if errors.Is(renameErr, os.ErrPermission) || strings.Contains(renameErr.Error(), "Access is denied") {
			return errors.New("permission denied. Please run with Administrator privileges")
		}
		return fmt.Errorf("failed to rename current executable: %w", renameErr)
	}

	data, err := io.ReadAll(src)
	if err != nil {
		if rErr := osRename(oldPath, execPath); rErr != nil {
			_ = rErr
		}
		return fmt.Errorf("failed to read new binary from archive: %w", err)
	}

	if writeErr := osWriteFile(execPath, data, 0o755); writeErr != nil {
		if rErr := osRename(oldPath, execPath); rErr != nil {
			_ = rErr
		}
		if errors.Is(writeErr, os.ErrPermission) {
			return errors.New("permission denied while writing new binary")
		}
		return fmt.Errorf("failed to write new binary: %w", writeErr)
	}

	return nil
}

// CleanupWindowsOldFiles removes any left-over .old files from previous updates on Windows.
func CleanupWindowsOldFiles() {
	if osGOOS != osWindows {
		return
	}
	execPath, err := osExecutable()
	if err != nil {
		return
	}
	execPath, err = filepathEvalSymlinks(execPath)
	if err != nil {
		return
	}
	if err = osRemove(execPath + ".old"); err != nil {
		_ = err
	}
}
