package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const maxBinary = 64 << 20
const maxUncompressedArchive = 256 << 20

type Installation string

const (
	Standalone Installation = "standalone"
	Homebrew   Installation = "homebrew"
	Container  Installation = "container"
	GoBuild    Installation = "go-build"
)

func Classify(executable, buildVersion string) Installation {
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil {
		resolved = executable
	}
	path := filepath.ToSlash(resolved)
	if strings.Contains(path, "/Cellar/ravel/") {
		return Homebrew
	}
	if path == "/opt/ravel/ravel" {
		return Container
	}
	if buildVersion == "dev" {
		return GoBuild
	}
	return Standalone
}

// Install replaces a standalone macOS/Linux executable with an archive's
// verified binary. The archive checksum is checked by DownloadArchive first.
func Install(ctx context.Context, release Release, archive []byte, executable string) error {
	if runtime.GOOS == "windows" {
		return errors.New("in-place update is unavailable on Windows; download the release archive")
	}
	archiveName, err := ArchiveName(release.Tag, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return err
	}
	info, err := os.Lstat(executable)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("executable is not a regular file; update it through its installer")
	}
	binary, err := binaryFromArchive(archive, strings.TrimSuffix(archiveName, ".tar.gz")+"/ravel")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(executable), ".ravel-update-*")
	if err != nil {
		return fmt.Errorf("cannot create update next to executable: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(checkCtx, name, "version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "ravel "+release.Tag {
		return fmt.Errorf("downloaded binary failed version check: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if err := os.Rename(name, executable); err != nil {
		return fmt.Errorf("cannot replace executable: %w", err)
	}
	return nil
}

func binaryFromArchive(archive []byte, wanted string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("invalid release archive: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var binary []byte
	var totalSize int64
	for entries := 0; ; entries++ {
		if entries > 1000 {
			return nil, errors.New("release archive has too many entries")
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid release archive: %w", err)
		}
		if hdr.Size < 0 || hdr.Size > maxUncompressedArchive-totalSize {
			return nil, errors.New("release archive is too large when unpacked")
		}
		totalSize += hdr.Size
		if hdr.Name != wanted {
			continue
		}
		if binary != nil || hdr.Typeflag != tar.TypeReg || hdr.Size <= 0 || hdr.Size > maxBinary {
			return nil, errors.New("release archive has an invalid executable entry")
		}
		binary, err = io.ReadAll(io.LimitReader(tr, maxBinary+1))
		if err != nil {
			return nil, err
		}
		if int64(len(binary)) != hdr.Size {
			return nil, errors.New("release executable size mismatch")
		}
	}
	if binary == nil {
		return nil, errors.New("release archive does not contain ravel executable")
	}
	return binary, nil
}
