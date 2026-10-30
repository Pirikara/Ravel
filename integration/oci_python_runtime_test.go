package integration_test

import (
	"archive/tar"
	"encoding/binary"
	"strings"
	"testing"
)

const ociPythonRuntimePath = "usr/local/lib/libpython3.13.so.1.0"

// This compact ELF carries the metadata needed for the integration test; the
// real-image smoke test checks an installed CPython shared library separately.
func ociTestPythonRuntimeELF(version string) []byte {
	data := make([]byte, 384)
	copy(data, "\x7fELF")
	data[4], data[5], data[6] = 2, 1, 1
	binary.LittleEndian.PutUint16(data[16:18], 3)  // ET_DYN
	binary.LittleEndian.PutUint16(data[18:20], 62) // x86-64
	binary.LittleEndian.PutUint32(data[20:24], 1)
	binary.LittleEndian.PutUint64(data[40:48], 64)
	binary.LittleEndian.PutUint16(data[52:54], 64)
	binary.LittleEndian.PutUint16(data[58:60], 64)
	binary.LittleEndian.PutUint16(data[60:62], 2)
	binary.LittleEndian.PutUint16(data[62:64], 1)
	binary.LittleEndian.PutUint32(data[132:136], 3) // SHT_STRTAB
	binary.LittleEndian.PutUint64(data[152:160], 192)
	binary.LittleEndian.PutUint64(data[160:168], 16)
	copy(data[192:], "\x00.shstrtab\x00")
	copy(data[240:], "Py_GetVersion\x00")
	copy(data[290:], "\x00"+version+"\x00")
	return data
}

func TestOCIPythonRuntimeLibraryEvidenceAndOverlay(t *testing.T) {
	ambiguous := ociTestPythonRuntimeELF("3.13.18")
	copy(ambiguous[330:], "\x003.13.20\x00")
	for _, test := range []struct {
		name      string
		upper     []ociTestEntry
		want      string
		wantIssue string
	}{
		{name: "base", want: "3.13.18"},
		{name: "whiteout", upper: []ociTestEntry{{name: "usr/local/lib/.wh.libpython3.13.so.1.0"}}},
		{name: "replacement", upper: []ociTestEntry{{name: ociPythonRuntimePath, data: ociTestPythonRuntimeELF("3.13.19")}}, want: "3.13.19"},
		{name: "invalid_replacement", upper: []ociTestEntry{{name: ociPythonRuntimePath, data: []byte("not an ELF")}}, wantIssue: "python_runtime_invalid"},
		{name: "version_mismatch", upper: []ociTestEntry{{name: ociPythonRuntimePath, data: ociTestPythonRuntimeELF("3.12.18")}}, wantIssue: "python_runtime_invalid"},
		{name: "ambiguous_version", upper: []ociTestEntry{{name: ociPythonRuntimePath, data: ambiguous}}, wantIssue: "python_runtime_invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			layout := ociTestLayout(t)
			layers := []ociTestLayer{{entries: []ociTestEntry{{name: ociPythonRuntimePath, data: ociTestPythonRuntimeELF("3.13.18")}}}}
			if test.upper != nil {
				layers = append(layers, ociTestLayer{entries: test.upper})
			}
			image := ociTestImage(t, layout, "linux", "amd64", layers)
			ociTestIndex(t, layout, image)
			doc, output, code := ociTestScan(t, layout)
			if code != 0 {
				t.Fatalf("Python runtime scan failed: code=%d output=%s", code, output)
			}
			if test.want == "" {
				if len(doc.Components) != 0 {
					t.Fatalf("removed or invalid Python runtime remained: %#v", doc.Components)
				}
			} else if len(doc.Components) != 1 || doc.Components[0].Name != "python" || doc.Components[0].Version != test.want || len(doc.Components[0].Hashes) != 1 || !strings.Contains(doc.Components[0].Context, "runtime=cpython;image=linux/amd64") || doc.Components[0].Evidence[0].Pointer == "" {
				t.Fatalf("Python runtime identity or evidence incorrect: %#v", doc.Components)
			}
			if test.wantIssue != "" {
				found := false
				for _, issue := range doc.Coverage.Issues {
					found = found || issue.Code == test.wantIssue
				}
				if !found {
					t.Fatalf("Python runtime issue missing: %#v", doc.Coverage.Issues)
				}
			}
		})
	}
}

func TestOCIPythonRuntimeLibraryUnderSameLayerSymlinkRejected(t *testing.T) {
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "amd64", []ociTestLayer{{entries: []ociTestEntry{
		{name: "usr/local/lib", typeflag: tar.TypeSymlink, linkname: "/outside"},
		{name: ociPythonRuntimePath, data: ociTestPythonRuntimeELF("3.13.18")},
	}}})
	ociTestIndex(t, layout, image)
	_, output, code := ociTestScan(t, layout)
	if code != 1 || !strings.Contains(output, "non-directory entry") {
		t.Fatalf("Python runtime beneath symlink accepted: code=%d output=%s", code, output)
	}
}
