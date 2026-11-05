package dpkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const maxDebArchive = 512 << 20
const maxDebControlArchive = 8 << 20
const maxDebControlTar = 16 << 20
const maxDebControlFile = 1 << 20

// CollectArchive reads package identity from a Debian binary archive. It does
// not claim that the package is installed or identify its distribution source.
func CollectArchive(file, project string) (model.Document, error) {
	f, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if !stat.Mode().IsRegular() || stat.Size() < 8 || stat.Size() > maxDebArchive {
		return model.Document{}, errors.New("Debian archive is empty or exceeds size limit")
	}
	var magic [8]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil || string(magic[:]) != "!<arch>\n" {
		return model.Document{}, errors.New("invalid Debian ar header")
	}
	var control []byte
	seenVersion, seenControl, seenData := false, false, false
	for pos, entries := int64(8), 0; pos < stat.Size(); entries++ {
		if entries >= 32 || stat.Size()-pos < 60 {
			return model.Document{}, errors.New("invalid Debian ar member count or header")
		}
		var header [60]byte
		if _, err := f.ReadAt(header[:], pos); err != nil || string(header[58:]) != "`\n" {
			return model.Document{}, errors.New("invalid Debian ar member header")
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(header[:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(header[48:58])), 10, 64)
		if err != nil || size < 0 || size > stat.Size()-pos-60 {
			return model.Document{}, errors.New("invalid Debian ar member size")
		}
		dataAt := pos + 60
		section := io.NewSectionReader(f, dataAt, size)
		switch {
		case name == "debian-binary":
			if seenVersion || size > 32 {
				return model.Document{}, errors.New("invalid Debian archive version member")
			}
			version, err := io.ReadAll(section)
			if err != nil || string(version) != "2.0\n" {
				return model.Document{}, errors.New("unsupported Debian archive version")
			}
			seenVersion = true
		case strings.HasPrefix(name, "control.tar"):
			if seenControl || size > maxDebControlArchive {
				return model.Document{}, errors.New("invalid Debian control archive")
			}
			control, err = debControl(section, name)
			if err != nil {
				return model.Document{}, err
			}
			seenControl = true
		case strings.HasPrefix(name, "data.tar"):
			if seenData {
				return model.Document{}, errors.New("duplicate Debian data archive")
			}
			seenData = true
		}
		pos = dataAt + size + size%2
		if pos > stat.Size() {
			return model.Document{}, errors.New("truncated Debian archive")
		}
	}
	if !seenVersion || !seenControl || !seenData {
		return model.Document{}, errors.New("incomplete Debian archive")
	}
	fields, err := debFields(control)
	if err != nil {
		return model.Document{}, err
	}
	name, version, arch := fields["Package"], fields["Version"], fields["Architecture"]
	if !packageName.MatchString(name) || version == "" || strings.ContainsAny(version, " \t\r\n\x00/\\") || !architecture.MatchString(arch) {
		return model.Document{}, errors.New("invalid Debian control identity")
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return model.Document{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return model.Document{}, err
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	ev := model.Evidence{Collector: "deb-archive", InputPath: file, InputDigest: "sha256:" + digest, Method: "artifact-inspection"}
	ref := "deb-archive:" + common.ID(digest)
	doc := common.NewDocument(file, project, "deb-archive", nil)
	doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: name, Version: version, Platform: arch, Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{ev}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "observed", Evidence: ev})
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "confirmed", Evidence: ev})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_graph_partial"}, model.Issue{Code: "distribution_source_unavailable", Name: name})
	common.Finalize(&doc)
	return doc, nil
}

func debControl(member io.Reader, name string) ([]byte, error) {
	var stream io.Reader = member
	var closeReader func()
	switch name {
	case "control.tar":
	case "control.tar.gz":
		r, err := gzip.NewReader(member)
		if err != nil {
			return nil, err
		}
		stream, closeReader = r, func() { _ = r.Close() }
	case "control.tar.xz":
		r, err := (xz.ReaderConfig{DictCap: 64 << 20}).NewReader(member)
		if err != nil {
			return nil, err
		}
		stream = r
	case "control.tar.zst":
		r, err := zstd.NewReader(member, zstd.WithDecoderMaxMemory(64<<20))
		if err != nil {
			return nil, err
		}
		stream, closeReader = r, r.Close
	default:
		return nil, fmt.Errorf("unsupported Debian control compression: %s", name)
	}
	if closeReader != nil {
		defer closeReader()
	}
	limited := &io.LimitedReader{R: stream, N: maxDebControlTar + 1}
	tarReader := tar.NewReader(limited)
	var control []byte
	count := 0
	for ; count < 1024; count++ {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("invalid Debian control tar: %w", err)
		}
		if h.Name != "control" && h.Name != "./control" || h.Typeflag != tar.TypeReg {
			continue
		}
		if control != nil || h.Size < 0 || h.Size > maxDebControlFile {
			return nil, errors.New("ambiguous or oversized Debian control file")
		}
		control, err = io.ReadAll(io.LimitReader(tarReader, maxDebControlFile+1))
		if err != nil || len(control) > maxDebControlFile {
			return nil, errors.New("Debian control file exceeds size limit")
		}
	}
	if count == 1024 {
		return nil, errors.New("Debian control tar has too many entries")
	}
	if limited.N <= 0 {
		return nil, errors.New("Debian control tar exceeds size limit")
	}
	if control == nil {
		return nil, errors.New("Debian control file missing")
	}
	return control, nil
}

func debFields(data []byte) (map[string]string, error) {
	fields := map[string]string{}
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		key, value, ok := strings.Cut(strings.TrimSuffix(string(line), "\r"), ":")
		if !ok || key == "" {
			return nil, errors.New("invalid Debian control field")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate Debian control field")
		}
		fields[key] = strings.TrimSpace(value)
	}
	return fields, nil
}
