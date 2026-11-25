package oci

import (
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestImageProductPURL(t *testing.T) {
	for _, tc := range []struct{ collector, name, version, kind, context, want string }{
		{"python-runtime-elf", "python", "3.13.4", "package", "", "pkg:generic/python@3.13.4"},
		{"ruby-runtime-elf", "ruby", "3.3.4", "package", "", "pkg:generic/ruby@3.3.4"},
		{"node-runtime-elf", "node", "22.0.0", "package", "", "pkg:generic/node@22.0.0"},
		{"go-buildinfo", "stdlib", "go1.27.3", "package", "", "pkg:golang/stdlib@1.27.3"},
		{"go-buildinfo", "app", "", "application", "main_module=example.org/Org/app", "pkg:golang/example.org/Org/app"},
		{"nuget-assembly", "core", "1.2.3", "package", "", ""},
		{"r-installed-description", "base", "4.4.2", "package", "", ""},
		{"wordpress-plugin", "Example", "1.0.0", "package", "", ""},
	} {
		t.Run(tc.collector+tc.name, func(t *testing.T) {
			c := model.Component{Name: tc.name, Version: tc.version, Kind: tc.kind, Context: tc.context, Evidence: []model.Evidence{{Collector: tc.collector}}}
			setImageProductPURL(&c)
			if c.PURL != tc.want || c.PURL != "" && c.PURLBasis != "ecosystem_inferred" {
				t.Fatalf("product coordinate: %#v", c)
			}
		})
	}
}

func TestRPMPURLPreservesCaseAndEpoch(t *testing.T) {
	c := model.Component{Name: "MixedCase", Version: "2:1.2.3-4.fc42", Platform: "x86_64"}
	setOSPackagePURL(&c, "usr/lib/sysimage/rpm/rpmdb.sqlite", osReleaseIdentity{id: "fedora", version: "42"})
	if c.PURL != "pkg:rpm/fedora/MixedCase@1.2.3-4.fc42?arch=x86_64&distro=fedora-42&epoch=2" || c.Version != "2:1.2.3-4.fc42" {
		t.Fatalf("RPM coordinates: %#v", c)
	}
}
