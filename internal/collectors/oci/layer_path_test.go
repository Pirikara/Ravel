package oci

import "testing"

func TestLayerPathAcceptsLiteralSystemdEscape(t *testing.T) {
	const name = `etc/systemd/system/dev-virtio\x2dports-org.qemu.guest_agent.0.device.wants`
	got, err := cleanLayerTarPath(name)
	if err != nil || got != name {
		t.Fatalf("safe Linux layer path rejected: got=%q err=%v", got, err)
	}
	if _, err := cleanTarPath(name); err == nil {
		t.Fatal("archive extraction path accepted a backslash")
	}
}

func TestLayerPathRejectsTraversal(t *testing.T) {
	for _, name := range []string{"../var/lib/dpkg/status", "/var/lib/dpkg/status", "etc/../var/lib/dpkg/status", "etc/\x00status"} {
		if _, err := cleanLayerTarPath(name); err == nil {
			t.Fatalf("unsafe Linux layer path accepted: %q", name)
		}
	}
}
