package rpm

import (
	"encoding/binary"
	"testing"
)

func TestDependencyHeaderRejectsOutOfBoundsIndexes(t *testing.T) {
	for _, data := range [][]byte{
		{},
		make([]byte, 8),
		{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0},
		{0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff},
	} {
		if _, _, ok := parseDependencyHeader(data); ok {
			t.Fatalf("malformed RPM header accepted: %x", data)
		}
	}
	badOffset := make([]byte, 8+16+1)
	binary.BigEndian.PutUint32(badOffset[:4], 1)
	binary.BigEndian.PutUint32(badOffset[4:8], 1)
	binary.BigEndian.PutUint32(badOffset[8:12], rpmTagName)
	binary.BigEndian.PutUint32(badOffset[12:16], rpmTypeString)
	binary.BigEndian.PutUint32(badOffset[16:20], 0xffffffff)
	binary.BigEndian.PutUint32(badOffset[20:24], 1)
	if _, _, ok := parseDependencyHeader(badOffset); ok {
		t.Fatal("out-of-bounds RPM tag offset accepted")
	}
}
