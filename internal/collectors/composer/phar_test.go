package composer

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPHARComposerMetadataAndApplication(t *testing.T) {
	for _, file := range []string{"stored.phar", "deflated.phar"} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../../testdata/archives/composer", file))
			if err != nil {
				t.Fatal(err)
			}
			doc, err := CollectPHAR(data, "oci:layer!/usr/bin/composer", "example", "usr/bin/composer")
			if err != nil {
				t.Fatal(err)
			}
			if len(doc.Components) != 3 {
				t.Fatal("embedded library/application inventory wrong", doc.Components)
			}
			apps := 0
			packages := 0
			outerDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(data))
			root := ""
			for _, c := range doc.Components {
				if c.Kind == "application" {
					apps++
					root = c.ID
					if c.Name != "composer" || c.Version != "2.9.1" || c.PURL != "pkg:generic/composer@2.9.1" || len(c.Hashes) != 1 {
						t.Fatal(c)
					}
					continue
				}
				packages++
				if len(c.Evidence) != 2 || c.Evidence[0].Collector != "composer-installed-phar" || c.Evidence[0].Method != "embedded-installed-metadata" || c.Evidence[1].InputDigest != outerDigest || len(c.Hashes) != 0 || len(c.Licenses) != 1 {
					t.Fatal("embedded metadata provenance incorrect", c)
				}
			}
			if apps != 1 || packages != 2 {
				t.Fatal(apps, packages)
			}
			installedEdges := 0
			for _, e := range doc.Edges {
				if e.From == root {
					installedEdges++
				}
			}
			if installedEdges != 2 {
				t.Fatal("bundled dependencies lost their application root", doc.Edges)
			}
		})
	}
}

func TestPHARInvalidOrDamagedDataIsNotInventoried(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/archives/composer/deflated.phar")
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), data...)
	changed[len(changed)/2] ^= 1
	for _, input := range [][]byte{nil, []byte("<?php echo 'ordinary script';"), data[:20], changed, data[:len(data)-1]} {
		if _, err := CollectPHAR(input, "input", "example", "app.phar"); err == nil {
			t.Fatal("invalid PHAR accepted")
		}
	}
}

func TestPHARMemberCRCIsCheckedSeparately(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/archives/composer/stored.phar")
	if err != nil {
		t.Fatal(err)
	}
	pos := bytes.Index(data, []byte("example/alpha"))
	if pos < 0 {
		t.Fatal("fixture metadata absent")
	}
	data[pos] = 'd'
	end := len(data) - 72
	sum := sha512.Sum512(data[:end])
	copy(data[end:end+64], sum[:])
	if _, err := CollectPHAR(data, "input", "example", "app.phar"); err == nil {
		t.Fatal("damaged member accepted despite inconsistent CRC")
	}
}
