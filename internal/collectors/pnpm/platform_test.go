package pnpm

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLibcFieldShapes(t *testing.T) {
	for _, test := range []struct {
		input string
		valid bool
		count int
	}{
		{"glibc", true, 1}, {"[glibc, musl]", true, 2}, {"[]", true, 0},
		{"true", false, 0}, {"123", false, 0}, {"[glibc, 123]", false, 0}, {"{name: glibc}", false, 0},
	} {
		var pkg packageEntry
		err := yaml.Unmarshal([]byte("libc: "+test.input), &pkg)
		if (err == nil) != test.valid || test.valid && len(pkg.Libc) != test.count {
			t.Fatalf("%s: %+v %v", test.input, pkg.Libc, err)
		}
	}
}
