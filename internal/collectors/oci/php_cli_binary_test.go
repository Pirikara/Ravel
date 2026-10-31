package oci

import "testing"

func TestPHPCLIVersionRejectsConflictingHeaders(t *testing.T) {
	data := []byte("\x00PHP %s (%s) (built: %s %s) (%s)\nCopyright (c) The PHP Group\n" +
		"\x00X-Powered-By: PHP/8.4.27\x00\x00X-Powered-By: PHP/8.4.26\x00" +
		"\x00Zend Engine v4.4.27, Copyright (c) Zend Technologies\n")
	if version, _, ok := phpCLIVersionInROData(data); ok || version != "" {
		t.Fatalf("conflicting PHP headers identified a runtime: %q", version)
	}
}
