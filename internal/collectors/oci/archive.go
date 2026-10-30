package oci

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"ravel/internal/model"
)

const (
	maxArchiveBytes   = 8 << 30
	maxExtractedBytes = 4 << 30
	maxArchiveEntries = 10000
)

var archiveBlobName = regexp.MustCompile(`^blobs/sha256/[0-9a-f]{64}$`)

// CollectArchive reads an OCI layout tar without trusting archive paths or
// extracting files unrelated to the image layout. The temporary layout is
// removed after its referenced blobs have been verified by Collect.
func CollectArchive(archive, project, platform string) (model.Document, error) {
	info, err := os.Lstat(archive)
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArchiveBytes {
		return model.Document{}, errors.New("image archive must be a regular file within the size limit")
	}
	file, err := os.Open(archive)
	if err != nil {
		return model.Document{}, err
	}
	var prefix [2]byte
	_, readErr := io.ReadFull(file, prefix[:])
	if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
		_ = file.Close()
		return model.Document{}, readErr
	}
	if prefix != [2]byte{0x1f, 0x8b} {
		_ = file.Close()
		return collectPlainArchive(archive, project, platform)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return model.Document{}, err
	}
	compressed, err := gzip.NewReader(file)
	if err != nil {
		_ = file.Close()
		return model.Document{}, err
	}
	temp, err := os.CreateTemp("", "ravel-image-*.tar")
	if err != nil {
		_ = compressed.Close()
		_ = file.Close()
		return model.Document{}, err
	}
	defer os.Remove(temp.Name())
	copied, copyErr := io.Copy(temp, io.LimitReader(compressed, maxArchiveBytes+1))
	closeTempErr := temp.Close()
	closeGzipErr := compressed.Close()
	closeFileErr := file.Close()
	if copyErr != nil {
		return model.Document{}, copyErr
	}
	if closeTempErr != nil || closeGzipErr != nil || closeFileErr != nil {
		return model.Document{}, errors.New("could not finish reading compressed image archive")
	}
	if copied > maxArchiveBytes {
		return model.Document{}, errors.New("decompressed image archive exceeds size limit")
	}
	doc, err := collectPlainArchive(temp.Name(), project, platform)
	if err != nil {
		return model.Document{}, err
	}
	doc.Source = archive
	doc.Sources = []string{archive}
	return doc, nil
}

func collectPlainArchive(archive, project, platform string) (model.Document, error) {
	info, err := os.Lstat(archive)
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxArchiveBytes {
		return model.Document{}, errors.New("OCI archive must be a regular tar file within the size limit")
	}
	file, err := os.Open(archive)
	if err != nil {
		return model.Document{}, err
	}
	defer file.Close()
	temp, err := os.MkdirTemp("", "ravel-oci-layout-")
	if err != nil {
		return model.Document{}, err
	}
	defer os.RemoveAll(temp)
	reader := tar.NewReader(file)
	seen := map[string]bool{}
	var extracted int64
	for entries := 0; ; entries++ {
		if entries >= maxArchiveEntries {
			return model.Document{}, errors.New("OCI archive has too many entries")
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return model.Document{}, err
		}
		name, err := cleanTarPath(header.Name)
		if err != nil {
			return model.Document{}, err
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return model.Document{}, fmt.Errorf("unsupported OCI archive entry: %s", name)
		}
		if name != "oci-layout" && name != "index.json" && !archiveBlobName.MatchString(name) {
			continue // optional layout files are not needed for this scan
		}
		if seen[name] {
			return model.Document{}, fmt.Errorf("duplicate OCI archive entry: %s", name)
		}
		seen[name] = true
		limit := int64(maxLayerBytes)
		if name == "oci-layout" || name == "index.json" {
			limit = maxMetadataBytes
		}
		if header.Size < 0 || header.Size > limit || extracted > maxExtractedBytes-header.Size {
			return model.Document{}, errors.New("OCI archive extraction limit exceeded")
		}
		extracted += header.Size
		path := filepath.Join(temp, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return model.Document{}, err
		}
		target, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return model.Document{}, err
		}
		_, copyErr := io.CopyN(target, reader, header.Size)
		closeErr := target.Close()
		if copyErr != nil {
			return model.Document{}, copyErr
		}
		if closeErr != nil {
			return model.Document{}, closeErr
		}
	}
	if !seen["oci-layout"] || !seen["index.json"] {
		if !seen["oci-layout"] && !seen["index.json"] {
			return collectLegacyDockerArchive(archive, project, platform)
		}
		return model.Document{}, errors.New("OCI archive lacks oci-layout or index.json")
	}
	doc, err := Collect(temp, project, platform)
	if err != nil {
		return model.Document{}, err
	}
	doc.Source = archive
	doc.Sources = []string{archive}
	return doc, nil
}
