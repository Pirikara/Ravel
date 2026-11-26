package integration_test

import (
	"path/filepath"
	"testing"
)

func TestPnpmScalarAndArrayLibc(t *testing.T) {
	doc := scanDevelopmentSample(t, filepath.Join("..", "testdata", "fixtures", "pnpm-libc-shapes", "pnpm-lock.yaml"))
	if len(doc.Components) != 2 {
		t.Fatal(doc.Components)
	}
	platforms := map[string]string{}
	for _, component := range doc.Components {
		platforms[component.Name] = component.Platform
	}
	if platforms["native-glibc"] != "linux/x64/glibc" || platforms["native-musl"] != "linux/arm64/musl" {
		t.Fatal(platforms)
	}
}
