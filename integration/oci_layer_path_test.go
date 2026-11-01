package integration_test

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"
)

func TestOCILayerWithSystemdEscapedName(t *testing.T) {
	status, err := os.ReadFile(filepath.Join("..", "testdata", "fixtures", "dpkg-basic", "var", "lib", "dpkg", "status"))
	if err != nil {
		t.Fatal(err)
	}
	layout := ociTestLayout(t)
	image := ociTestImage(t, layout, "linux", "arm64", []ociTestLayer{{entries: []ociTestEntry{
		{name: `etc/systemd/system/dev-virtio\x2dports-org.qemu.guest_agent.0.device.wants`, typeflag: tar.TypeDir},
		{name: "var/lib/dpkg/status", data: status},
	}}})
	ociTestIndex(t, layout, image)
	doc, output, code := ociTestScan(t, layout)
	if code != 0 || doc.Coverage.Packages != 4 {
		t.Fatalf("safe systemd layer entry blocked package scan: code=%d output=%s coverage=%#v", code, output, doc.Coverage)
	}
}
