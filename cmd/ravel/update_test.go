package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUpgradeHomebrewVerifiesInstalledVersion(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell test")
	}
	dir := t.TempDir()
	brew := filepath.Join(dir, "brew")
	script := "#!/bin/sh\nif [ \"$1 $2 $3\" = 'upgrade pirikara/tap/ravel ' ]; then exit 0; fi\nif [ \"$1 $2 $3\" = 'list --versions pirikara/tap/ravel' ]; then echo \"ravel $RAVEL_TEST_BREW_VERSION\"; exit 0; fi\nexit 2\n"
	if err := os.WriteFile(brew, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RAVEL_TEST_BREW_VERSION", "0.1.0-beta.4")
	if err := upgradeHomebrew(context.Background(), "v0.1.0-beta.4"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RAVEL_TEST_BREW_VERSION", "0.1.0-beta.3")
	if err := upgradeHomebrew(context.Background(), "v0.1.0-beta.4"); err == nil || !strings.Contains(err.Error(), "does not yet provide") {
		t.Fatalf("outdated tap accepted: %v", err)
	}
}
