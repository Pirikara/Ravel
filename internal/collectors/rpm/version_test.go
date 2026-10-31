package rpm

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestCompareRPMEVR(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		{"1.0", "2.0", -1, true},
		{"2.0", "1.0", 1, true},
		{"1.2.0", "1.2", 1, true},
		{"1.002", "1.10", -1, true},
		{"1:1.0", "0:99.0", 1, true},
		{"1.0-1", "2.0-9", -1, true},
		{"1.0-1", "1.0-2", -1, true},
		{"1.0-1.fc42", "1.0-1.fc41", 1, true},
		{"1.0", "01.0", 0, true},
		{"1..0", "1+0", 0, true},
		{"1.0~beta", "1.0", -1, true},
		{"1.0~beta2", "1.0~beta1", 1, true},
		{"1.0^git1", "1.0", 1, true},
		{"1.0^git1", "1.0.1", -1, true},
		{"1.0a", "1.0.1", -1, true},
		{"1.0-1", "1.0", 0, false},
		{"1.0", "1.0-1", 0, false},
		{"1:1.0", "x:2.0", 0, false},
		{"1.0-1-2", "1.0-1", 0, false},
	} {
		cmp, ok := compareRPMEVR(tc.a, tc.b)
		if cmp != tc.cmp || ok != tc.ok {
			t.Errorf("compareRPMEVR(%q, %q) = (%d, %t), want (%d, %t)", tc.a, tc.b, cmp, ok, tc.cmp, tc.ok)
		}
	}
}

func TestRPMVersionReferenceCorpus(t *testing.T) {
	input, err := os.Open("testdata/version_corpus.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	scanner := bufio.NewScanner(input)
	count := 0
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) != 3 {
			t.Fatalf("invalid RPM reference row %d: %q", count+1, scanner.Text())
		}
		want, err := strconv.Atoi(fields[2])
		if err != nil {
			t.Fatal(err)
		}
		got, ok := compareRPMEVR(fields[0], fields[1])
		if !ok || got != want {
			t.Errorf("RPM reference row %d: %q vs %q = (%d, %t), want %d", count+1, fields[0], fields[1], got, ok, want)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 980 {
		t.Fatalf("RPM version reference corpus has %d rows, want 980", count)
	}
}

func TestRPMConstraintClaims(t *testing.T) {
	for _, tc := range []struct {
		name               string
		requirement, offer headerDependency
		known, offerKnown  bool
		condition          string
		possible           bool
	}{
		{"equal", headerDependency{version: "1.0", flags: rpmSenseEqual}, headerDependency{version: "1.0", flags: rpmSenseEqual}, true, true, "", true},
		{"greater satisfied", headerDependency{version: "2.0", flags: rpmSenseGreater | rpmSenseEqual}, headerDependency{version: "3.0", flags: rpmSenseEqual}, true, true, "", true},
		{"greater unsatisfied", headerDependency{version: "2.0", flags: rpmSenseGreater | rpmSenseEqual}, headerDependency{version: "1.0", flags: rpmSenseEqual}, true, true, "", false},
		{"unversioned", headerDependency{}, headerDependency{}, true, false, "", true},
		{"unknown requirement", headerDependency{}, headerDependency{}, false, true, "rpm_constraint=unverified", true},
		{"range offer", headerDependency{version: "2.0", flags: rpmSenseGreater | rpmSenseEqual}, headerDependency{version: "3.0", flags: rpmSenseGreater}, true, true, "rpm_constraint=unverified", true},
		{"prerelease satisfied", headerDependency{version: "1.0~beta", flags: rpmSenseGreater | rpmSenseEqual}, headerDependency{version: "1.0", flags: rpmSenseEqual}, true, true, "", true},
		{"prerelease unsatisfied", headerDependency{version: "1.0~beta", flags: rpmSenseLess}, headerDependency{version: "1.0", flags: rpmSenseEqual}, true, true, "", false},
		{"release satisfied", headerDependency{version: "1.0-2", flags: rpmSenseGreater | rpmSenseEqual}, headerDependency{version: "1.0-3", flags: rpmSenseEqual}, true, true, "", true},
		{"release unsatisfied", headerDependency{version: "1.0-2", flags: rpmSenseGreater | rpmSenseEqual}, headerDependency{version: "1.0-1", flags: rpmSenseEqual}, true, true, "", false},
		{"requirement release omitted equal", headerDependency{version: "1.0", flags: rpmSenseEqual}, headerDependency{version: "1.0-1", flags: rpmSenseEqual}, true, true, "", true},
		{"requirement release omitted greater-or-equal", headerDependency{version: "1.0", flags: rpmSenseGreater | rpmSenseEqual}, headerDependency{version: "1.0-1", flags: rpmSenseEqual}, true, true, "", true},
		{"requirement release omitted strict-greater", headerDependency{version: "1.0", flags: rpmSenseGreater}, headerDependency{version: "1.0-1", flags: rpmSenseEqual}, true, true, "", false},
		{"provider release omitted", headerDependency{version: "1.0-1", flags: rpmSenseEqual}, headerDependency{version: "1.0", flags: rpmSenseEqual}, true, true, "rpm_constraint=unverified", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			condition, possible := rpmConstraint(tc.requirement, tc.known, rpmProvider{version: tc.offer.version, flags: tc.offer.flags, known: tc.offerKnown})
			if condition != tc.condition || possible != tc.possible {
				t.Fatalf("rpmConstraint = (%q, %t), want (%q, %t)", condition, possible, tc.condition, tc.possible)
			}
		})
	}
}
