package dpkg

import (
	"os/exec"
	"testing"
)

func TestDebianVersionOrdering(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0~rc1", "1.0", -1},
		{"1.0~~", "1.0~", -1},
		{"1.0", "1.0+deb12u1", -1},
		{"1.0a", "1.0+", -1},
		{"1.0-1", "1.0-2", -1},
		{"1.0-1+b1", "1.0-1", 1},
		{"1:1.0", "2.0", 1},
		{"0:1.0", "1.0", 0},
		{"1.0-0", "1.0", 0},
		{"1.0002", "1.2", 0},
		{"1.0-1~bpo12", "1.0-1", -1},
		{"12.4+deb12u9", "12.4", 1},
	}
	for _, tc := range cases {
		got, ok := compareVersions(tc.a, tc.b)
		if !ok || got != tc.want {
			t.Errorf("compareVersions(%q, %q) = %d, %v; want %d", tc.a, tc.b, got, ok, tc.want)
		}
		if _, err := exec.LookPath("dpkg"); err == nil {
			op := "eq"
			if tc.want < 0 {
				op = "lt"
			} else if tc.want > 0 {
				op = "gt"
			}
			if output, err := exec.Command("dpkg", "--compare-versions", tc.a, op, tc.b).CombinedOutput(); err != nil {
				t.Errorf("dpkg disagrees for %q %s %q: %v: %s", tc.a, op, tc.b, err, output)
			}
		}
	}
	for _, invalid := range []string{"", "x1", "1.0 bad", "1::2", "1.0-", "1.0/2"} {
		if _, ok := compareVersions(invalid, "1.0"); ok {
			t.Errorf("malformed version %q was accepted", invalid)
		}
	}
}
