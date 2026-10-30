package apk

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	adbInstalledSchema = 0x00626469 // "idb\x00"
	adbValueMask       = 0x0fffffff
	adbTypeArray       = 0xd
	adbTypeObject      = 0xe
	maxADBPackages     = 100000
)

// parseInstalledADB reads the package-info subset of apk-tools' v3 installed
// database. The outer database embeds one package ADB block per array item.
// File contents and scripts in those blocks are outside this collector's scope.
func parseInstalledADB(data []byte) ([]installedPackage, error) {
	if len(data) < 4 || !bytes.Equal(data[:3], []byte("ADB")) {
		return nil, errors.New("invalid APK v3 header")
	}
	switch data[3] {
	case 'd':
		reader := flate.NewReader(bytes.NewReader(data[4:]))
		defer reader.Close()
		plain, err := io.ReadAll(io.LimitReader(reader, maxInstalledBytes+1))
		if err != nil || len(plain) > maxInstalledBytes {
			return nil, errors.New("APK v3 database decompression failed or exceeded size limit")
		}
		data = plain
	case '.':
	case 'c':
		return nil, errors.New("unsupported APK v3 compression")
	default:
		return nil, errors.New("unsupported APK v3 header")
	}
	if len(data) < 8 || !bytes.Equal(data[:4], []byte("ADB.")) || binary.LittleEndian.Uint32(data[4:8]) != adbInstalledSchema {
		return nil, errors.New("invalid APK v3 installed database schema")
	}
	outer, err := adbBlockPayload(data[8:])
	if err != nil {
		return nil, err
	}
	root, err := outer.object(outer.root(), adbTypeObject)
	if err != nil {
		return nil, fmt.Errorf("invalid APK v3 root: %w", err)
	}
	entries, err := outer.object(adbField(root, 1), adbTypeArray)
	if err != nil {
		return nil, fmt.Errorf("invalid APK v3 package array: %w", err)
	}
	if len(entries)-1 > maxADBPackages {
		return nil, errors.New("APK v3 database has too many packages")
	}
	packages := make([]installedPackage, 0, len(entries)-1)
	for i := 1; i < len(entries); i++ {
		blob, err := outer.blob(entries[i])
		if err != nil || len(blob) < 12 {
			return nil, fmt.Errorf("invalid APK v3 package %d block", i)
		}
		packageData, err := adbBlockPayload(blob)
		if err != nil {
			return nil, fmt.Errorf("invalid APK v3 package %d: %w", i, err)
		}
		packageRoot, err := packageData.object(packageData.root(), adbTypeObject)
		if err != nil {
			return nil, fmt.Errorf("invalid APK v3 package %d root: %w", i, err)
		}
		info, err := packageData.object(adbField(packageRoot, 1), adbTypeObject)
		if err != nil {
			return nil, fmt.Errorf("invalid APK v3 package %d info: %w", i, err)
		}
		name, err := packageData.blobString(adbField(info, 1))
		if err != nil {
			return nil, err
		}
		version, err := packageData.blobString(adbField(info, 2))
		if err != nil {
			return nil, err
		}
		arch, err := packageData.blobString(adbField(info, 5))
		if err != nil {
			return nil, err
		}
		if !packageName.MatchString(name) || version == "" || strings.ContainsAny(version, " \t\r\n\x00") || !architecture.MatchString(arch) {
			return nil, fmt.Errorf("invalid APK v3 package %d identity", i)
		}
		depends, err := packageData.dependencies(adbField(info, 15))
		if err != nil {
			return nil, fmt.Errorf("invalid APK v3 package %d dependencies: %w", i, err)
		}
		provides, err := packageData.dependencies(adbField(info, 16))
		if err != nil {
			return nil, fmt.Errorf("invalid APK v3 package %d provides: %w", i, err)
		}
		packages = append(packages, installedPackage{name: name, version: version, arch: arch, depends: strings.Join(depends, " "), provides: strings.Join(provides, " ")})
	}
	return packages, nil
}

type adbReader struct{ data []byte }

func adbBlockPayload(data []byte) (adbReader, error) {
	if len(data) < 12 {
		return adbReader{}, errors.New("truncated APK v3 block")
	}
	word := binary.LittleEndian.Uint32(data[:4])
	if word>>30 != 0 {
		return adbReader{}, errors.New("APK v3 block is not an ADB block")
	}
	rawSize := int(word & 0x3fffffff)
	if rawSize < 12 || rawSize > len(data) || (rawSize+7)&^7 > len(data) {
		return adbReader{}, errors.New("invalid APK v3 block size")
	}
	for next := (rawSize + 7) &^ 7; next < len(data); {
		if len(data)-next < 4 {
			return adbReader{}, errors.New("truncated APK v3 signature block")
		}
		trailing := binary.LittleEndian.Uint32(data[next:])
		length := int(trailing & 0x3fffffff)
		if trailing>>30 != 1 || length < 4 || (length+7)&^7 > len(data)-next {
			return adbReader{}, errors.New("unexpected APK v3 trailing block")
		}
		next += (length + 7) &^ 7
	}
	payload := data[4:rawSize]
	if len(payload) < 8 || payload[0] != 0 {
		return adbReader{}, errors.New("unsupported APK v3 ADB compatibility version")
	}
	return adbReader{data: payload}, nil
}

func (r adbReader) root() uint32 { return binary.LittleEndian.Uint32(r.data[4:8]) }

func (r adbReader) object(tag uint32, want uint32) ([]uint32, error) {
	if tag>>28 != want && !(want == adbTypeArray && tag>>28 == adbTypeObject) {
		return nil, errors.New("unexpected APK v3 value type")
	}
	offset := int(tag & adbValueMask)
	if offset < 0 || offset > len(r.data)-4 {
		return nil, errors.New("invalid APK v3 object offset")
	}
	count := int(binary.LittleEndian.Uint32(r.data[offset:]))
	if count < 1 || count > (len(r.data)-offset)/4 {
		return nil, errors.New("invalid APK v3 object size")
	}
	values := make([]uint32, count)
	for i := range values {
		values[i] = binary.LittleEndian.Uint32(r.data[offset+4*i:])
	}
	return values, nil
}

func adbField(values []uint32, field int) uint32 {
	if field >= len(values) {
		return 0
	}
	return values[field]
}

func (r adbReader) blob(tag uint32) ([]byte, error) {
	if tag == 0 {
		return nil, nil
	}
	var header int
	switch tag >> 28 {
	case 8:
		header = 1
	case 9:
		header = 2
	case 10:
		header = 4
	default:
		return nil, errors.New("unexpected APK v3 blob type")
	}
	offset := int(tag & adbValueMask)
	if offset < 0 || offset > len(r.data)-header {
		return nil, errors.New("invalid APK v3 blob offset")
	}
	var size int
	switch header {
	case 1:
		size = int(r.data[offset])
	case 2:
		size = int(binary.LittleEndian.Uint16(r.data[offset:]))
	case 4:
		size = int(binary.LittleEndian.Uint32(r.data[offset:]))
	}
	if size < 0 || size > len(r.data)-offset-header {
		return nil, errors.New("invalid APK v3 blob size")
	}
	return r.data[offset+header : offset+header+size], nil
}

func (r adbReader) blobString(tag uint32) (string, error) {
	value, err := r.blob(tag)
	if err != nil || len(value) > 4096 || bytes.IndexByte(value, 0) >= 0 {
		return "", errors.New("invalid APK v3 string")
	}
	return string(value), nil
}

func (r adbReader) number(tag uint32) (uint64, error) {
	if tag == 0 {
		return 0, nil
	}
	offset := int(tag & adbValueMask)
	switch tag >> 28 {
	case 1:
		return uint64(tag & adbValueMask), nil
	case 2:
		if offset <= len(r.data)-4 {
			return uint64(binary.LittleEndian.Uint32(r.data[offset:])), nil
		}
	case 3:
		if offset <= len(r.data)-8 {
			return binary.LittleEndian.Uint64(r.data[offset:]), nil
		}
	}
	return 0, errors.New("invalid APK v3 integer")
}

func (r adbReader) dependencies(tag uint32) ([]string, error) {
	if tag == 0 {
		return nil, nil
	}
	entries, err := r.object(tag, adbTypeArray)
	if err != nil || len(entries) > 100001 {
		return nil, errors.New("invalid APK v3 dependency array")
	}
	result := make([]string, 0, len(entries)-1)
	for i := 1; i < len(entries); i++ {
		fields, err := r.object(entries[i], adbTypeObject)
		if err != nil {
			return nil, err
		}
		name, err := r.blobString(adbField(fields, 1))
		if err != nil || !depName.MatchString(name) {
			return nil, errors.New("invalid APK v3 dependency name")
		}
		version, err := r.blobString(adbField(fields, 2))
		if err != nil || strings.ContainsAny(version, " \t\r\n") {
			return nil, errors.New("invalid APK v3 dependency version")
		}
		match, err := r.number(adbField(fields, 3))
		if err != nil {
			return nil, err
		}
		prefix := ""
		if match&16 != 0 {
			prefix = "!"
		}
		if version == "" {
			if match != 0 && match != 7 && match != 16 && match != 23 {
				result = append(result, name+"@unsupported")
			} else {
				result = append(result, prefix+name)
			}
			continue
		}
		if match == 0 {
			match = 1 // equal is omitted from the wire format
		}
		op := map[uint64]string{1: "=", 2: "<", 3: "<=", 4: ">", 5: ">=", 9: "~"}[match&^uint64(16)]
		if op == "" {
			result = append(result, name+"@unsupported")
			continue
		}
		result = append(result, prefix+name+op+version)
	}
	return result, nil
}
