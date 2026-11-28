package composer

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	packageurl "github.com/package-url/packageurl-go"
)

const MaxPHARBytes = 32 << 20

type pharEntry struct {
	name                         string
	size, compressed, crc, flags uint32
	offset                       int
}

// CollectPHAR reads native PHAR manifests and Composer installed.json without
// loading PHP or deserializing PHP metadata. Checksums detect damaged input;
// they do not authenticate the publisher or prove individual library contents.
func CollectPHAR(data []byte, source, project, archivePath string) (model.Document, error) {
	files, err := pharComposerFiles(data)
	if err != nil {
		return model.Document{}, err
	}
	const member = "vendor/composer/installed.json"
	metadata, ok := files[member]
	if !ok {
		return model.Document{}, errors.New("PHAR has no Composer installed.json")
	}
	doc, err := CollectInstalled(metadata, source+"!phar/"+member, project, archivePath+"!phar/"+member)
	if err != nil {
		return model.Document{}, err
	}
	digest := sha256.Sum256(data)
	outer := model.Evidence{Collector: "composer-phar", InputPath: source, InputDigest: "sha256:" + hex.EncodeToString(digest[:]), Method: "embedded-archive"}
	rewrite := func(e *model.Evidence) {
		e.Collector = "composer-installed-phar"
		e.Method = "embedded-installed-metadata"
	}
	for i := range doc.Components {
		c := &doc.Components[i]
		for j := range c.Evidence {
			rewrite(&c.Evidence[j])
		}
		c.Evidence = append(c.Evidence, outer)
		c.Context += ";archive=/" + archivePath
		for j := range c.Licenses {
			for k := range c.Licenses[j].Evidence {
				rewrite(&c.Licenses[j].Evidence[k])
			}
		}
	}
	for i := range doc.Edges {
		rewrite(&doc.Edges[i].Evidence)
	}
	for i := range doc.Origins {
		rewrite(&doc.Origins[i].Evidence)
	}
	for i := range doc.Development {
		rewrite(&doc.Development[i].Evidence)
	}
	if code := files["src/Composer/Composer.php"]; bytes.Contains(code, []byte("namespace Composer;")) {
		matches := pharComposerVersion.FindAllSubmatch(code, -1)
		if len(matches) == 1 && pharReleaseVersion.Match(matches[0][1]) {
			version := string(matches[0][1])
			id := "composer-phar:" + common.ID(source+"\x00"+version)
			e := outer
			e.Pointer = "phar/src/Composer/Composer.php/VERSION"
			doc.Components = append(doc.Components, model.Component{ID: id, Kind: "application", Name: "composer", Version: version, PURL: packageurl.NewPackageURL("generic", "", "composer", version, nil, "").ToString(), Context: "location=/" + archivePath, Hashes: []model.Hash{{Alg: "SHA-256", Content: hex.EncodeToString(digest[:])}}, Evidence: []model.Evidence{e}})
			for i := range doc.Edges {
				if doc.Edges[i].From == "root" {
					doc.Edges[i].From = id
				}
			}
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: e})
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: archivePath})
		}
	}
	doc.Source = source
	doc.Coverage.Manager = "composer-phar"
	common.Finalize(&doc)
	return doc, nil
}

var pharComposerVersion = regexp.MustCompile(`(?m)^[\t ]*(?:public[\t ]+)?const[\t ]+VERSION[\t ]*=[\t ]*['"]([^'"\r\n]+)['"][\t ]*;`)
var pharReleaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`)

func pharComposerFiles(data []byte) (map[string][]byte, error) {
	if len(data) == 0 || len(data) > MaxPHARBytes {
		return nil, errors.New("PHAR exceeded size limit")
	}
	limit := len(data)
	if limit > 1<<20 {
		limit = 1 << 20
	}
	const halt = "__HALT_COMPILER();"
	index := bytes.Index(data[:limit], []byte(halt))
	if index < 0 {
		return nil, errors.New("native PHAR stub not found")
	}
	pos := index + len(halt)
	if len(data)-pos >= 3 && (data[pos] == ' ' || data[pos] == '\n') && string(data[pos+1:pos+3]) == "?>" {
		pos += 3
		if len(data)-pos >= 2 && string(data[pos:pos+2]) == "\r\n" {
			pos += 2
		} else if pos < len(data) && data[pos] == '\n' {
			pos++
		}
	}
	if len(data)-pos < 4 {
		return nil, errors.New("truncated PHAR manifest")
	}
	length := int(binary.LittleEndian.Uint32(data[pos:]))
	pos += 4
	if length < 18 || length > 1<<20 || length > len(data)-pos {
		return nil, errors.New("invalid PHAR manifest length")
	}
	manifest := bytes.NewReader(data[pos : pos+length])
	contentStart := pos + length
	read32 := func() (uint32, error) {
		var v uint32
		err := binary.Read(manifest, binary.LittleEndian, &v)
		return v, err
	}
	skip := func(n uint32) error {
		if uint64(n) > uint64(manifest.Len()) {
			return io.ErrUnexpectedEOF
		}
		_, err := manifest.Seek(int64(n), io.SeekCurrent)
		return err
	}
	count, err := read32()
	if err != nil || count == 0 || count > 20000 {
		return nil, errors.New("invalid PHAR entry count")
	}
	var api uint16
	if err = binary.Read(manifest, binary.BigEndian, &api); err != nil || api != 0x1000 && api != 0x1100 && api != 0x1110 {
		return nil, errors.New("unsupported PHAR API version")
	}
	flags, err := read32()
	if err != nil {
		return nil, err
	}
	alias, err := read32()
	if err != nil {
		return nil, err
	}
	if err = skip(alias); err != nil {
		return nil, err
	}
	meta, err := read32()
	if err != nil {
		return nil, err
	}
	if err = skip(meta); err != nil {
		return nil, err
	}
	end := len(data)
	if flags&0x10000 != 0 {
		if end < 8 || string(data[end-4:]) != "GBMB" {
			return nil, errors.New("invalid PHAR checksum footer")
		}
		var h hash.Hash
		switch binary.LittleEndian.Uint32(data[end-8:]) {
		case 1:
			h = md5.New()
		case 2:
			h = sha1.New()
		case 3:
			h = sha256.New()
		case 4:
			h = sha512.New()
		default:
			return nil, errors.New("unsupported PHAR signature type")
		}
		if end < 8+h.Size() {
			return nil, errors.New("truncated PHAR checksum")
		}
		end -= 8 + h.Size()
		h.Write(data[:end])
		if !bytes.Equal(h.Sum(nil), data[end:end+h.Size()]) {
			return nil, errors.New("PHAR checksum mismatch")
		}
	}
	entries := make([]pharEntry, 0, count)
	offset := contentStart
	seen := map[string]bool{}
	for range count {
		n, err := read32()
		if err != nil || n == 0 || n > 4096 || uint64(n) > uint64(manifest.Len()) {
			return nil, errors.New("invalid PHAR filename")
		}
		nameBytes := make([]byte, n)
		if _, err = io.ReadFull(manifest, nameBytes); err != nil {
			return nil, err
		}
		name := string(nameBytes)
		clean := strings.TrimSuffix(name, "/")
		if path.Clean(clean) != clean || path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") || strings.ContainsAny(clean, "\\\x00") || seen[name] {
			return nil, errors.New("invalid or duplicate PHAR member")
		}
		seen[name] = true
		e := pharEntry{name: name, offset: offset}
		values := []*uint32{&e.size, new(uint32), &e.compressed, &e.crc, &e.flags, &meta}
		for _, v := range values {
			if err = binary.Read(manifest, binary.LittleEndian, v); err != nil {
				return nil, err
			}
		}
		if err = skip(meta); err != nil {
			return nil, err
		}
		if offset > end || uint64(e.compressed) > uint64(end-offset) {
			return nil, errors.New("PHAR member exceeds archive")
		}
		offset += int(e.compressed)
		entries = append(entries, e)
	}
	if manifest.Len() != 0 || offset != end {
		return nil, errors.New("PHAR content/manifest length mismatch")
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if e.name != "vendor/composer/installed.json" && e.name != "src/Composer/Composer.php" {
			continue
		}
		if e.size > 8<<20 {
			return nil, errors.New("embedded Composer metadata exceeded size limit")
		}
		var reader io.Reader = bytes.NewReader(data[e.offset : e.offset+int(e.compressed)])
		var closer io.Closer
		switch e.flags & 0x3000 {
		case 0:
		case 0x1000:
			r := flate.NewReader(reader)
			reader, closer = r, r
		case 0x2000:
			reader = bzip2.NewReader(reader)
		default:
			return nil, errors.New("invalid PHAR compression flags")
		}
		content, err := io.ReadAll(io.LimitReader(reader, int64(e.size)+1))
		if closer != nil {
			closer.Close()
		}
		if err != nil || len(content) != int(e.size) || crc32.ChecksumIEEE(content) != e.crc {
			return nil, errors.New("invalid compressed PHAR member")
		}
		files[e.name] = content
	}
	return files, nil
}
