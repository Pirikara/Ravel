package rpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	rpmutils "github.com/sassoftware/go-rpmutils"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

const maxRPMArchive = 512 << 20
const maxRPMHeader = 16 << 20

// CollectArchive identifies the package in a supplied RPM archive. The RPM
// header, not the filename, supplies the identity. A local archive alone does
// not establish installation state or a repository URL.
func CollectArchive(file, project string) (model.Document, error) {
	f, err := os.Open(file)
	if err != nil {
		return model.Document{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() < 128 || info.Size() > maxRPMArchive {
		return model.Document{}, errors.New("RPM archive is empty or exceeds size limit")
	}
	if err := checkRPMHeaderBounds(f, info.Size()); err != nil {
		return model.Document{}, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return model.Document{}, err
	}
	archive, err := rpmutils.ReadRpm(io.LimitReader(f, maxRPMHeader*2+256))
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid RPM archive: %w", err)
	}
	identity, err := archive.Header.GetNEVRA()
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid RPM package identity: %w", err)
	}
	if !packageName.MatchString(identity.Name) || identity.Version == "" || identity.Release == "" || strings.ContainsAny(identity.Version+identity.Release, " \t\r\n\x00/\\") || !architecture.MatchString(identity.Arch) {
		return model.Document{}, errors.New("invalid RPM package identity")
	}
	version := identity.Version + "-" + identity.Release
	if identity.Epoch != "" && identity.Epoch != "0" {
		epoch, err := strconv.ParseUint(identity.Epoch, 10, 31)
		if err != nil {
			return model.Document{}, errors.New("invalid RPM epoch")
		}
		version = strconv.FormatUint(epoch, 10) + ":" + version
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return model.Document{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return model.Document{}, err
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	ev := model.Evidence{Collector: "rpm-archive", InputPath: file, InputDigest: "sha256:" + digest, Method: "artifact-inspection"}
	ref := "rpm-archive:" + common.ID(digest)
	doc := common.NewDocument(file, project, "rpm-archive", nil)
	doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: identity.Name, Version: version, Platform: identity.Arch, Hashes: []model.Hash{{Alg: "SHA-256", Content: digest}}, Evidence: []model.Evidence{ev}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: ref, Kind: "observed", Evidence: ev})
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "confirmed", Evidence: ev})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "artifact_graph_partial"}, model.Issue{Code: "distribution_source_unavailable", Name: identity.Name})
	common.Finalize(&doc)
	return doc, nil
}

// The upstream RPM reader allocates according to the header lengths. Check
// both header tables and data areas before passing untrusted bytes to it.
func checkRPMHeaderBounds(f *os.File, fileSize int64) error {
	var lead [96]byte
	if _, err := f.ReadAt(lead[:], 0); err != nil || binary.BigEndian.Uint32(lead[:4]) != 0xedabeedb {
		return errors.New("invalid RPM lead")
	}
	pos := int64(96)
	for block := 0; block < 2; block++ {
		var intro [16]byte
		if _, err := f.ReadAt(intro[:], pos); err != nil || intro[0] != 0x8e || intro[1] != 0xad || intro[2] != 0xe8 {
			return errors.New("invalid RPM header intro")
		}
		count := uint64(binary.BigEndian.Uint32(intro[8:12]))
		size := uint64(binary.BigEndian.Uint32(intro[12:16]))
		if count > maxRPMHeader/16 || size > maxRPMHeader || count*16+size > maxRPMHeader {
			return errors.New("RPM header exceeds size limit")
		}
		if block == 0 {
			size = (size + 7) / 8 * 8
		}
		entries := make([]byte, count*16)
		data := make([]byte, size)
		if _, err := f.ReadAt(entries, pos+16); err != nil {
			return errors.New("truncated RPM entry table")
		}
		if _, err := f.ReadAt(data, pos+16+int64(len(entries))); err != nil {
			return errors.New("truncated RPM header data")
		}
		identityTags := map[uint32]bool{}
		for offset := uint64(0); offset < uint64(len(entries)); offset += 16 {
			tag := entries[offset : offset+16]
			id := binary.BigEndian.Uint32(tag[:4])
			kind := binary.BigEndian.Uint32(tag[4:8])
			at := uint64(binary.BigEndian.Uint32(tag[8:12]))
			n := uint64(binary.BigEndian.Uint32(tag[12:16]))
			if at > uint64(len(data)) || n > maxRPMHeader {
				return errors.New("invalid RPM header entry bounds")
			}
			if block == 1 && (id == 1000 || id == 1001 || id == 1002 || id == 1022) {
				if n != 1 || kind != 6 && kind != 8 && kind != 9 {
					return errors.New("invalid RPM identity header")
				}
				identityTags[id] = true
			}
			width := uint64(0)
			switch kind {
			case 0:
				width = 0
			case 1, 2, 7:
				width = 1
			case 3:
				width = 2
			case 4:
				width = 4
			case 5:
				width = 8
			case 6, 8, 9:
				cursor := at
				for i := uint64(0); i < n; i++ {
					end := bytes.IndexByte(data[cursor:], 0)
					if end < 0 {
						return errors.New("unterminated RPM header string")
					}
					cursor += uint64(end) + 1
				}
				continue
			default:
				return errors.New("unsupported RPM header entry type")
			}
			if n*width > uint64(len(data))-at {
				return errors.New("invalid RPM header entry size")
			}
		}
		if block == 1 && (!identityTags[1000] || !identityTags[1001] || !identityTags[1002] || !identityTags[1022]) {
			return errors.New("missing RPM identity header")
		}
		pos += 16 + int64(count*16+size)
		if pos > fileSize {
			return errors.New("truncated RPM header")
		}
	}
	return nil
}
