package integration_test

import (
	"archive/tar"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

const (
	ociNodeBinaryPath = "usr/local/bin/node"
	ociNodeHeaderPath = "usr/local/include/node/node_version.h"
)

func ociTestNodeRuntimeELF(versions ...string) []byte {
	data := make([]byte, 384)
	copy(data, "\x7fELF")
	data[4], data[5], data[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(data[16:18], 3)
	binary.LittleEndian.PutUint16(data[18:20], 62)
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[32:40], 64)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[54:56], 56)
	binary.LittleEndian.PutUint16(data[56:58], 1)
	for i, version := range versions {
		copy(data[96+i*64:], "node.js/v"+version+"\x00")
	}
	return data
}

func ociTestNodeVersionHeader(major, minor, patch int) []byte {
	return []byte(fmt.Sprintf("#define NODE_MAJOR_VERSION %d\n#define NODE_MINOR_VERSION %d\n#define NODE_PATCH_VERSION %d\n#define NODE_VERSION_IS_RELEASE 1\n", major, minor, patch))
}

func TestOCINodeRuntimeEvidenceAndOverlay(t *testing.T) {
	malformedELF := ociTestNodeRuntimeELF("24.22.1")
	binary.LittleEndian.PutUint64(malformedELF[32:40], 0)
	base := []ociTestEntry{
		{name: ociNodeBinaryPath, data: ociTestNodeRuntimeELF("24.22.1")},
		{name: ociNodeHeaderPath, data: ociTestNodeVersionHeader(24, 22, 1)},
	}
	for _, test := range []struct {
		name         string
		lower        []ociTestEntry
		upper        []ociTestEntry
		want         string
		wantIssue    string
		wantEvidence int
	}{
		{name: "binary_and_header", want: "24.22.1", wantEvidence: 2},
		{name: "binary_only", lower: []ociTestEntry{{name: ociNodeBinaryPath, data: ociTestNodeRuntimeELF("24.22.1")}}, want: "24.22.1", wantEvidence: 1},
		{name: "header_whiteout", upper: []ociTestEntry{{name: "usr/local/include/node/.wh.node_version.h"}}, want: "24.22.1", wantEvidence: 1},
		{name: "binary_whiteout", upper: []ociTestEntry{{name: "usr/local/bin/.wh.node"}}},
		{name: "binary_replacement_and_matching_header", upper: []ociTestEntry{{name: ociNodeBinaryPath, data: ociTestNodeRuntimeELF("24.22.2")}, {name: ociNodeHeaderPath, data: ociTestNodeVersionHeader(24, 22, 2)}}, want: "24.22.2", wantEvidence: 2},
		{name: "binary_replacement_mismatch", upper: []ociTestEntry{{name: ociNodeBinaryPath, data: ociTestNodeRuntimeELF("24.22.2")}}, wantIssue: "node_runtime_version_mismatch"},
		{name: "header_replacement_mismatch", upper: []ociTestEntry{{name: ociNodeHeaderPath, data: ociTestNodeVersionHeader(24, 22, 2)}}, wantIssue: "node_runtime_version_mismatch"},
		{name: "invalid_binary", upper: []ociTestEntry{{name: ociNodeBinaryPath, data: []byte("node.js/v24.22.1\x00")}}, wantIssue: "node_runtime_invalid"},
		{name: "malformed_elf", upper: []ociTestEntry{{name: ociNodeBinaryPath, data: malformedELF}}, wantIssue: "node_runtime_invalid"},
		{name: "version_unavailable", upper: []ociTestEntry{{name: ociNodeBinaryPath, data: ociTestNodeRuntimeELF()}}, wantIssue: "node_runtime_version_unavailable"},
		{name: "ambiguous_binary", upper: []ociTestEntry{{name: ociNodeBinaryPath, data: ociTestNodeRuntimeELF("24.22.1", "24.22.2")}}, wantIssue: "node_runtime_invalid"},
		{name: "invalid_header", upper: []ociTestEntry{{name: ociNodeHeaderPath, data: []byte("#define NODE_MAJOR_VERSION 24\n")}}, want: "24.22.1", wantIssue: "node_runtime_header_invalid", wantEvidence: 1},
		{name: "contradictory_header", upper: []ociTestEntry{{name: ociNodeHeaderPath, data: append(ociTestNodeVersionHeader(24, 22, 1), []byte("#define NODE_VERSION_IS_RELEASE 0\n")...)}}, want: "24.22.1", wantIssue: "node_runtime_header_invalid", wantEvidence: 1},
		{name: "binary_symlink_replacement", upper: []ociTestEntry{{name: ociNodeBinaryPath, typeflag: tar.TypeSymlink, linkname: "/outside"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			lower := base
			if test.lower != nil {
				lower = test.lower
			}
			layers := []ociTestLayer{{entries: lower}}
			if test.upper != nil {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			layout := ociTestLayout(t)
			image := ociTestImage(t, layout, "linux", "amd64", layers)
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("Node runtime scan failed: code=%d output=%s", code, output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 {
					t.Fatalf("removed or invalid Node runtime remained: %#v", doc.Components)
				}
			} else if len(doc.Components) != 1 || doc.Components[0].Name != "node" || doc.Components[0].Version != test.want || len(doc.Components[0].Evidence) != test.wantEvidence || len(doc.Components[0].Hashes) != 1 || !strings.Contains(doc.Components[0].Context, "runtime=nodejs;image=linux/amd64") || doc.Components[0].Evidence[0].Pointer == "" {
				t.Fatalf("Node runtime identity or evidence incorrect: %#v", doc.Components)
			}
			if test.wantIssue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == test.wantIssue
				}
				if !found {
					t.Fatalf("Node runtime issue %s missing: %#v", test.wantIssue, doc.Coverage.Issues)
				}
			}
		})
	}
}

func TestOCINodeRuntimeMarkerAcrossScanWindow(t *testing.T) {
	binary := make([]byte, 130<<10)
	copy(binary, ociTestNodeRuntimeELF())
	copy(binary[(64<<10)-5:], "node.js/v24.22.1\x00")
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{{name: ociNodeBinaryPath, data: binary}}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || len(doc.Components) != 1 || doc.Components[0].Version != "24.22.1" {
		t.Fatalf("Node runtime marker across scan window lost: code=%d output=%s components=%#v", code, output, doc.Components)
	}
}

func TestOCINodeRuntimeUnderSameLayerSymlinkRejected(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/bin", typeflag: tar.TypeSymlink, linkname: "/outside"},
		{name: ociNodeBinaryPath, data: ociTestNodeRuntimeELF("24.22.1")},
	}}})
	ociTestIndex(t, layout, image)
	_, output, code := ociTestScan(t, layout)
	if code != 1 || !strings.Contains(output, "non-directory entry") {
		t.Fatalf("Node runtime beneath symlink accepted: code=%d output=%s", code, output)
	}
}
