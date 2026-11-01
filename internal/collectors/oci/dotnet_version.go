package oci

import (
	"bytes"
	"encoding/binary"
	"path"
	"regexp"
	"strings"
)

var managedProductVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.+_-]{0,127}$`)

// managedPEVersion accepts only a single, well-bounded PE VERSIONINFO resource
// whose internal filename and description agree with the assembly filename.
// A version resource is evidence for this file, not for a NuGet distribution.
func managedPEVersion(data []byte) (string, string) {
	if len(data) < 64 {
		return "", ""
	}
	peOffset := uint64(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	pe := boundedPESlice(data, peOffset, 24)
	if pe == nil || !bytes.Equal(pe[:4], []byte("PE\x00\x00")) {
		return "", ""
	}
	sections := int(binary.LittleEndian.Uint16(pe[6:8]))
	optionalBytes := uint64(binary.LittleEndian.Uint16(pe[20:22]))
	if sections == 0 || sections > 96 {
		return "", ""
	}
	optionalOffset := peOffset + 24
	optional := boundedPESlice(data, optionalOffset, optionalBytes)
	if len(optional) < 2 {
		return "", ""
	}
	var directories int
	switch binary.LittleEndian.Uint16(optional[:2]) {
	case 0x10b:
		directories = 96
	case 0x20b:
		directories = 112
	default:
		return "", ""
	}
	if len(optional) < directories+3*8 {
		return "", ""
	}
	entry := optional[directories+2*8 : directories+3*8]
	rva, size := binary.LittleEndian.Uint32(entry[:4]), binary.LittleEndian.Uint32(entry[4:8])
	if rva == 0 || size < 24 || size > 1<<20 {
		return "", ""
	}
	sectionTable := boundedPESlice(data, optionalOffset+optionalBytes, uint64(sections)*40)
	if sectionTable == nil {
		return "", ""
	}
	resources := peRVASlice(data, sectionTable, rva, size)
	if resources == nil {
		return "", ""
	}
	root, ok := resourceEntries(resources, 0)
	if !ok {
		return "", ""
	}
	var versionData []byte
	for i := 0; i < len(root); i += 8 {
		id := binary.LittleEndian.Uint32(root[i : i+4])
		child := binary.LittleEndian.Uint32(root[i+4 : i+8])
		if id != 16 || child&0x80000000 == 0 {
			continue
		}
		names, valid := resourceEntries(resources, child&0x7fffffff)
		if !valid || len(names) > 16*8 {
			return "", ""
		}
		for j := 0; j < len(names); j += 8 {
			nameChild := binary.LittleEndian.Uint32(names[j+4 : j+8])
			if nameChild&0x80000000 == 0 {
				return "", ""
			}
			languages, valid := resourceEntries(resources, nameChild&0x7fffffff)
			if !valid || len(languages) > 16*8 {
				return "", ""
			}
			for k := 0; k < len(languages); k += 8 {
				leaf := binary.LittleEndian.Uint32(languages[k+4 : k+8])
				if leaf&0x80000000 != 0 || versionData != nil {
					return "", ""
				}
				description := boundedPESlice(resources, uint64(leaf), 16)
				if description == nil {
					return "", ""
				}
				dataRVA := binary.LittleEndian.Uint32(description[:4])
				dataSize := binary.LittleEndian.Uint32(description[4:8])
				if dataSize == 0 || dataSize > 64<<10 {
					return "", ""
				}
				versionData = peRVASlice(data, sectionTable, dataRVA, dataSize)
				if versionData == nil {
					return "", ""
				}
			}
		}
	}
	if versionData == nil {
		return "", ""
	}
	fields, ok := versionResourceStrings(versionData)
	if !ok {
		return "", ""
	}
	internal := fields["InternalName"]
	description := fields["FileDescription"]
	version := fields["ProductVersion"]
	if internal == "" || !strings.HasSuffix(strings.ToLower(internal), ".dll") || description != strings.TrimSuffix(internal, ".dll") || !managedProductVersion.MatchString(version) || path.Base(internal) != internal {
		return "", ""
	}
	return description, version
}

func resourceEntries(data []byte, offset uint32) ([]byte, bool) {
	header := boundedPESlice(data, uint64(offset), 16)
	if header == nil {
		return nil, false
	}
	count := int(binary.LittleEndian.Uint16(header[12:14])) + int(binary.LittleEndian.Uint16(header[14:16]))
	if count == 0 || count > 128 {
		return nil, false
	}
	entries := boundedPESlice(data, uint64(offset)+16, uint64(count)*8)
	return entries, entries != nil
}

type versionBlock struct {
	key      string
	value    []byte
	children int
	end      int
}

func readVersionBlock(data []byte, start int) (versionBlock, bool) {
	if start < 0 || start+6 > len(data) {
		return versionBlock{}, false
	}
	length := int(binary.LittleEndian.Uint16(data[start : start+2]))
	valueLength := int(binary.LittleEndian.Uint16(data[start+2 : start+4]))
	valueType := binary.LittleEndian.Uint16(data[start+4 : start+6])
	end := start + length
	if length < 8 || end > len(data) || valueType > 1 {
		return versionBlock{}, false
	}
	position := start + 6
	var key []byte
	for len(key) < 128 && position+2 <= end {
		c := binary.LittleEndian.Uint16(data[position : position+2])
		position += 2
		if c == 0 {
			break
		}
		if c < 0x20 || c > 0x7e {
			return versionBlock{}, false
		}
		key = append(key, byte(c))
	}
	if binary.LittleEndian.Uint16(data[position-2:position]) != 0 {
		return versionBlock{}, false
	}
	position = (position + 3) &^ 3
	if valueType == 1 {
		valueLength *= 2
	}
	if position > end || valueLength > end-position {
		return versionBlock{}, false
	}
	children := (position + valueLength + 3) &^ 3
	if children > end+3 {
		return versionBlock{}, false
	}
	if children > end {
		children = end
	}
	return versionBlock{key: string(key), value: data[position : position+valueLength], children: children, end: end}, true
}

func walkVersionChildren(data []byte, parent versionBlock, visit func(versionBlock) bool) bool {
	for position := parent.children; position+6 <= parent.end; {
		child, ok := readVersionBlock(data[:parent.end], position)
		if !ok || !visit(child) {
			return false
		}
		position = (child.end + 3) &^ 3
	}
	return true
}

func versionResourceStrings(data []byte) (map[string]string, bool) {
	root, ok := readVersionBlock(data, 0)
	if !ok || root.key != "VS_VERSION_INFO" || len(root.value) != 52 || binary.LittleEndian.Uint32(root.value[:4]) != 0xFEEF04BD {
		return nil, false
	}
	fields := map[string]string{}
	ok = walkVersionChildren(data, root, func(info versionBlock) bool {
		if info.key != "StringFileInfo" {
			return true
		}
		return walkVersionChildren(data, info, func(table versionBlock) bool {
			return walkVersionChildren(data, table, func(field versionBlock) bool {
				if field.key != "InternalName" && field.key != "FileDescription" && field.key != "ProductVersion" {
					return true
				}
				if len(field.value) < 2 || len(field.value) > 258 || len(field.value)%2 != 0 {
					return false
				}
				value := make([]byte, 0, len(field.value)/2)
				terminated := false
				for i := 0; i < len(field.value); i += 2 {
					c := binary.LittleEndian.Uint16(field.value[i : i+2])
					if c == 0 {
						if i != len(field.value)-2 {
							return false
						}
						terminated = true
						break
					}
					if c < 0x20 || c > 0x7e {
						return false
					}
					value = append(value, byte(c))
				}
				if !terminated {
					return false
				}
				if previous, found := fields[field.key]; found && previous != string(value) {
					return false
				}
				fields[field.key] = string(value)
				return true
			})
		})
	})
	return fields, ok
}
