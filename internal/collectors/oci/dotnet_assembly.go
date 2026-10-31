package oci

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
)

const (
	maxDotnetAssemblyBytes      = 16 << 20
	maxDotnetAssemblyLayerBytes = 128 << 20
	maxDotnetAssemblyFiles      = 20000
)

type dotnetAssemblyState struct {
	digest string
	layer  string
	status string
}

func inspectDotnetAssembly(data []byte) dotnetAssemblyState {
	if !isManagedAssembly(data) {
		return dotnetAssemblyState{status: "invalid"}
	}
	hash := sha256.Sum256(data)
	return dotnetAssemblyState{digest: "sha256:" + hex.EncodeToString(hash[:])}
}

// isManagedAssembly checks the PE CLR directory and CLI metadata root with
// bounded slices. OCI layers are untrusted, so this does not use debug/pe,
// whose Go documentation explicitly warns against adversarial input.
func isManagedAssembly(data []byte) bool {
	if len(data) < 64 || !bytes.Equal(data[:2], []byte("MZ")) {
		return false
	}
	peOffset := uint64(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	pe := boundedPESlice(data, peOffset, 24)
	if pe == nil || !bytes.Equal(pe[:4], []byte("PE\x00\x00")) {
		return false
	}
	sections := int(binary.LittleEndian.Uint16(pe[6:8]))
	optionalBytes := uint64(binary.LittleEndian.Uint16(pe[20:22]))
	if sections == 0 || sections > 96 {
		return false
	}
	optionalOffset := peOffset + 24
	optional := boundedPESlice(data, optionalOffset, optionalBytes)
	if optional == nil || len(optional) < 2 {
		return false
	}
	var directories, countOffset int
	switch binary.LittleEndian.Uint16(optional[:2]) {
	case 0x10b: // PE32
		directories, countOffset = 96, 92
	case 0x20b: // PE32+
		directories, countOffset = 112, 108
	default:
		return false
	}
	if len(optional) < directories+15*8 || binary.LittleEndian.Uint32(optional[countOffset:countOffset+4]) < 15 {
		return false
	}
	clrDirectory := optional[directories+14*8 : directories+15*8]
	clrRVA := binary.LittleEndian.Uint32(clrDirectory[:4])
	clrSize := binary.LittleEndian.Uint32(clrDirectory[4:8])
	if clrRVA == 0 || clrSize < 72 {
		return false
	}
	sectionTable := boundedPESlice(data, optionalOffset+optionalBytes, uint64(sections)*40)
	if sectionTable == nil {
		return false
	}
	clr := peRVASlice(data, sectionTable, clrRVA, 72)
	if clr == nil || binary.LittleEndian.Uint32(clr[:4]) < 72 {
		return false
	}
	metadataRVA := binary.LittleEndian.Uint32(clr[8:12])
	metadataSize := binary.LittleEndian.Uint32(clr[12:16])
	if metadataRVA == 0 || metadataSize < 20 {
		return false
	}
	metadata := peRVASlice(data, sectionTable, metadataRVA, metadataSize)
	if metadata == nil || !bytes.Equal(metadata[:4], []byte("BSJB")) {
		return false
	}
	versionSize := uint64(binary.LittleEndian.Uint32(metadata[12:16]))
	streamHeader := uint64(16) + ((versionSize + 3) &^ uint64(3))
	if versionSize == 0 || versionSize > 1024 || streamHeader+4 > uint64(len(metadata)) {
		return false
	}
	count := int(binary.LittleEndian.Uint16(metadata[streamHeader+2 : streamHeader+4]))
	if count == 0 || count > 64 {
		return false
	}
	current := streamHeader + 4
	hasAssemblyTable := false
	hasStrings := false
	for i := 0; i < count; i++ {
		if current+9 > uint64(len(metadata)) {
			return false
		}
		offset := uint64(binary.LittleEndian.Uint32(metadata[current : current+4]))
		size := uint64(binary.LittleEndian.Uint32(metadata[current+4 : current+8]))
		nameStart := current + 8
		nameEnd := nameStart
		for nameEnd < uint64(len(metadata)) && nameEnd-nameStart < 32 && metadata[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd == uint64(len(metadata)) || nameEnd-nameStart == 32 || offset > uint64(len(metadata)) || size > uint64(len(metadata))-offset {
			return false
		}
		name := string(metadata[nameStart:nameEnd])
		if name == "#~" || name == "#-" {
			if hasAssemblyTable {
				return false
			}
			tables := metadata[offset : offset+size]
			if len(tables) < 24 {
				return false
			}
			// ECMA-335 II.24.2.6: Valid bit 0x20 denotes the Assembly
			// table, and row counts follow the 24-byte stream header.
			valid := binary.LittleEndian.Uint64(tables[8:16])
			rowsEnd := 24 + 4*bits.OnesCount64(valid)
			if valid&(uint64(1)<<32) == 0 || rowsEnd+22 > len(tables) {
				return false
			}
			assemblyRows := 24 + 4*bits.OnesCount64(valid&((uint64(1)<<32)-1))
			if binary.LittleEndian.Uint32(tables[assemblyRows:assemblyRows+4]) != 1 {
				return false
			}
			hasAssemblyTable = true
		} else if name == "#Strings" {
			if hasStrings || size == 0 {
				return false
			}
			hasStrings = true
		}
		current = nameStart + ((nameEnd - nameStart + 4) &^ uint64(3))
	}
	return hasAssemblyTable && hasStrings
}

func boundedPESlice(data []byte, offset, size uint64) []byte {
	if offset > uint64(len(data)) || size > uint64(len(data))-offset {
		return nil
	}
	return data[offset : offset+size]
}

func peRVASlice(data, sections []byte, rva, size uint32) []byte {
	var found []byte
	for i := 0; i < len(sections); i += 40 {
		section := sections[i : i+40]
		virtualSize := binary.LittleEndian.Uint32(section[8:12])
		virtualAddress := binary.LittleEndian.Uint32(section[12:16])
		rawSize := binary.LittleEndian.Uint32(section[16:20])
		rawOffset := binary.LittleEndian.Uint32(section[20:24])
		span := virtualSize
		if rawSize > span {
			span = rawSize
		}
		if rva < virtualAddress || uint64(rva)-uint64(virtualAddress) >= uint64(span) {
			continue
		}
		delta := uint64(rva) - uint64(virtualAddress)
		if delta+uint64(size) > uint64(rawSize) {
			return nil
		}
		mapped := boundedPESlice(data, uint64(rawOffset)+delta, uint64(size))
		if mapped == nil || found != nil {
			return nil
		}
		found = mapped
	}
	return found
}
