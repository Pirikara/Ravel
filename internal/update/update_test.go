package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestLatestSelectsChannelBySemver(t *testing.T) {
	releases := []Release{
		{Tag: "v0.1.0-beta.4", Prerelease: true},
		{Tag: "v0.1.0-beta.3", Prerelease: true},
		{Tag: "v0.1.0", Draft: true},
		{Tag: "v0.0.9"},
		{Tag: "v0.0.8"},
	}
	data, err := json.Marshal(releases)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/releases" || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("unexpected request: %s", r.URL)
		}
		w.Write(data)
	}))
	defer server.Close()
	client := NewClient("v0.1.0-beta.3")
	client.APIURL = server.URL
	for _, tc := range []struct{ channel, want string }{{"beta", "v0.1.0-beta.4"}, {"stable", "v0.0.9"}} {
		got, err := client.Latest(context.Background(), tc.channel)
		if err != nil || got.Tag != tc.want {
			t.Fatalf("%s: got %+v, %v", tc.channel, got, err)
		}
	}
	if comparison, err := Compare("v0.1.0-beta.3", "v0.1.0-beta.4"); err != nil || comparison >= 0 {
		t.Fatalf("version comparison: %d, %v", comparison, err)
	}
}

func TestDownloadArchiveRequiresMatchingDigests(t *testing.T) {
	const tag = "v0.1.0-beta.4"
	name := "ravel_" + tag + "_linux_amd64.tar.gz"
	archive := []byte("archive bytes")
	archiveSum := fmt.Sprintf("%x", sha256.Sum256(archive))
	checksums := []byte(archiveSum + "  " + name + "\n")
	asset := Asset{Name: name, Size: int64(len(archive)), Digest: "sha256:" + archiveSum, State: "uploaded"}
	sumAsset := Asset{Name: "SHA256SUMS", Size: int64(len(checksums)), Digest: fmt.Sprintf("sha256:%x", sha256.Sum256(checksums)), State: "uploaded"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case name:
			w.Write(archive)
		case "SHA256SUMS":
			w.Write(checksums)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient(tag)
	client.DownloadURL = server.URL
	release := Release{Tag: tag, Assets: []Asset{asset, sumAsset}}
	got, err := client.DownloadArchive(context.Background(), release, name)
	if err != nil || !bytes.Equal(got, archive) {
		t.Fatalf("valid archive rejected: %v", err)
	}
	bad := release
	bad.Assets = append([]Asset(nil), release.Assets...)
	bad.Assets[0].Digest = "sha256:" + strings.Repeat("0", 64)
	if _, err := client.DownloadArchive(context.Background(), bad, name); err == nil || !strings.Contains(err.Error(), "SHA256SUMS") {
		t.Fatalf("mismatched checksums accepted: %v", err)
	}
	bad.Assets = append([]Asset(nil), release.Assets...)
	bad.Assets[1].Digest = "sha256:" + strings.Repeat("0", 64)
	if _, err := client.DownloadArchive(context.Background(), bad, name); err == nil || !strings.Contains(err.Error(), "release metadata") {
		t.Fatalf("mismatched checksum asset accepted: %v", err)
	}
}

func TestInstallVerifiesBinaryBeforeReplacing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("in-place updates are unavailable on Windows")
	}
	const tag = "v0.1.0-beta.4"
	archiveName, err := ArchiveName(tag, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	executable := filepath.Join(dir, "ravel")
	old := []byte("old binary")
	if err := os.WriteFile(executable, old, 0o755); err != nil {
		t.Fatal(err)
	}
	entry := strings.TrimSuffix(archiveName, ".tar.gz") + "/ravel"
	wrong := archiveWithBinary(t, entry, []byte("#!/bin/sh\necho ravel wrong\n"))
	if err := Install(context.Background(), Release{Tag: tag}, wrong, executable); err == nil {
		t.Fatal("binary with wrong version accepted")
	}
	if data, err := os.ReadFile(executable); err != nil || !bytes.Equal(data, old) {
		t.Fatalf("old executable changed after failed update: %v", err)
	}
	good := archiveWithBinary(t, entry, []byte("#!/bin/sh\necho ravel "+tag+"\n"))
	if err := Install(context.Background(), Release{Tag: tag}, good, executable); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(executable); err != nil || !bytes.Equal(data, []byte("#!/bin/sh\necho ravel "+tag+"\n")) {
		t.Fatalf("new executable missing: %v", err)
	}
}

func archiveWithBinary(t *testing.T, name string, binary []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestClassifyInstallation(t *testing.T) {
	if Classify("/opt/homebrew/Cellar/ravel/0.1.0-beta.3/bin/ravel", "v0.1.0-beta.3") != Homebrew ||
		Classify("/opt/ravel/ravel", "v0.1.0-beta.3") != Container ||
		Classify("/tmp/ravel", "dev") != GoBuild ||
		Classify("/tmp/ravel", "v0.1.0-beta.3") != Standalone {
		t.Fatal("installation classification failed")
	}
}
