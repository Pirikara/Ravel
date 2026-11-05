package integration_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestPackageArchiveScanAndDiscovery(t *testing.T) {
	root := t.TempDir()
	fixtures := filepath.Join(root, "fixtures")
	if err := os.Mkdir(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	deb := filepath.Join(fixtures, "misleading_9_arm64.deb")
	rpm := filepath.Join(fixtures, "also-misleading.rpm")
	if err := os.WriteFile(deb, testDebArchive(t), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rpm, testRPMArchive(), 0o644); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(fixtures, "chart.tgz")
	if err := os.WriteFile(unknown, testGenericTarball(t), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ path, name, version, arch string }{
		{deb, "real-deb", "1.2.3-4", "amd64"},
		{rpm, "real-rpm", "2.3-5", "x86_64"},
	} {
		cmd := exec.Command(executable, "scan", test.path, "--format", "ravel-json")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("direct scan %s: %v", test.path, err)
		}
		var doc model.Document
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatal(err)
		}
		if len(doc.Components) != 1 || doc.Components[0].Name != test.name || doc.Components[0].Version != test.version || doc.Components[0].Platform != test.arch || len(doc.Components[0].Hashes) != 1 || doc.Components[0].PURL != "" {
			t.Fatalf("wrong archive identity: %#v", doc.Components)
		}
		if len(doc.Origins) != 1 || doc.Origins[0].Kind != "local" || doc.Edges[0].Kind != "observed" || doc.Coverage.GraphState != "partial" || doc.Coverage.OriginState != "partial" {
			t.Fatalf("archive claims unsupported facts: %#v", doc)
		}
	}
	if out, err := exec.Command(executable, "scan", root, "--all", "--recursive", "--include-archives", "--format", "ravel-json").CombinedOutput(); err == nil || !strings.Contains(string(out), "no statically scannable inputs") {
		t.Fatalf("default fixture exclusion failed: %v %s", err, out)
	}
	out, err := exec.Command(executable, "scan", root, "--all", "--recursive", "--include-test-and-vendor", "--include-archives", "--format", "ravel-json").Output()
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 2 || len(doc.Coverage.Inputs) != 2 {
		t.Fatalf("archive discovery lost inputs: %#v", doc.Coverage)
	}
	foundSkipped := false
	for _, issue := range doc.Coverage.Issues {
		foundSkipped = foundSkipped || issue.Code == "collector_skipped_unidentified_archive"
	}
	if !foundSkipped {
		t.Fatalf("unidentified archive was not reported: %#v", doc.Coverage.Issues)
	}
	if out, err := exec.Command(executable, "scan", root, "--include-archives").CombinedOutput(); err == nil || !strings.Contains(string(out), "requires --all --recursive") {
		t.Fatalf("option guard missing: %v %s", err, out)
	}
}

func testGenericTarball(t *testing.T) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{Name: "Chart.yaml", Mode: 0o644, Size: 0}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func TestRPMArchiveRejectsOversizedHeader(t *testing.T) {
	data := testRPMArchive()
	// Signature header entry count is at byte 104.
	binary.BigEndian.PutUint32(data[104:108], 0xffffffff)
	path := filepath.Join(t.TempDir(), "oversized.rpm")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(executable, "scan", path, "--format", "ravel-json").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "header exceeds size limit") {
		t.Fatalf("unsafe RPM header accepted: %v %s", err, out)
	}
}

func testDebArchive(t *testing.T) []byte {
	t.Helper()
	var controlTar bytes.Buffer
	tw := tar.NewWriter(&controlTar)
	control := []byte("Package: real-deb\nVersion: 1.2.3-4\nArchitecture: amd64\nDepends: libc6 (>= 2.0)\n")
	if err := tw.WriteHeader(&tar.Header{Name: "./control", Mode: 0o644, Size: int64(len(control))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(control); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(controlTar.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	archive.WriteString("!<arch>\n")
	for _, member := range []struct {
		name string
		data []byte
	}{
		{"debian-binary", []byte("2.0\n")},
		{"control.tar.gz", compressed.Bytes()},
		{"data.tar.gz", []byte("unused-data")},
	} {
		archive.WriteString(fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n", member.name, 0, 0, 0, 0o100644, len(member.data)))
		archive.Write(member.data)
		if len(member.data)%2 != 0 {
			archive.WriteByte('\n')
		}
	}
	return archive.Bytes()
}

func testRPMArchive() []byte {
	lead := make([]byte, 96)
	binary.BigEndian.PutUint32(lead[:4], 0xedabeedb)
	var archive bytes.Buffer
	archive.Write(lead)
	writeRPMHeader := func(fields map[uint32]string) {
		keys := []uint32{1000, 1001, 1002, 1022}
		if len(fields) == 0 {
			keys = nil
		}
		var entries, data bytes.Buffer
		for _, key := range keys {
			binary.Write(&entries, binary.BigEndian, key)
			binary.Write(&entries, binary.BigEndian, uint32(6))
			binary.Write(&entries, binary.BigEndian, uint32(data.Len()))
			binary.Write(&entries, binary.BigEndian, uint32(1))
			data.WriteString(fields[key])
			data.WriteByte(0)
		}
		archive.Write([]byte{0x8e, 0xad, 0xe8, 1, 0, 0, 0, 0})
		binary.Write(&archive, binary.BigEndian, uint32(len(keys)))
		binary.Write(&archive, binary.BigEndian, uint32(data.Len()))
		archive.Write(entries.Bytes())
		archive.Write(data.Bytes())
	}
	writeRPMHeader(nil)
	writeRPMHeader(map[uint32]string{1000: "real-rpm", 1001: "2.3", 1002: "5", 1022: "x86_64"})
	return archive.Bytes()
}
