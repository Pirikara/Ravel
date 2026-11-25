package oci

import (
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestPublicAuditableCrateDoesNotCorrelatePrivateOrGitLock(t *testing.T) {
	installed := model.Component{Kind: "package", Name: "demo", Version: "1.0.0", Context: "source=crates.io"}
	for _, purl := range []string{
		"pkg:cargo/demo@1.0.0",
		"pkg:cargo/demo@1.0.0?repository_url=https:%2F%2Fprivate.example.test%2Findex",
		"pkg:cargo/demo@1.0.0?vcs_url=git%2Bhttps:%2F%2Fcode.example.test%2Fdemo%40abcdef1234567",
	} {
		candidate := model.Component{Kind: "package", Name: "demo", Version: "1.0.0", PURL: purl}
		if got := imageLockCompatible(imageLockDocument{}, candidate, installed, "cargo"); got != (purl == "pkg:cargo/demo@1.0.0") {
			t.Fatalf("source boundary lost: %s => %t", purl, got)
		}
	}
}
