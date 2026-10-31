package rpm

import "testing"

func TestCompareNumericRPMEVR(t *testing.T) {
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
		{"1.0-1", "1.0-2", 0, false},
		{"1.0", "01.0", 0, false},
		{"1.0~beta", "1.0", 0, false},
		{"1..0", "1.0", 0, false},
		{"1:1.0", "x:2.0", 0, false},
	} {
		cmp, ok := compareNumericRPMEVR(tc.a, tc.b)
		if cmp != tc.cmp || ok != tc.ok {
			t.Errorf("compareNumericRPMEVR(%q, %q) = (%d, %t), want (%d, %t)", tc.a, tc.b, cmp, ok, tc.cmp, tc.ok)
		}
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
		{"complex version", headerDependency{version: "1.0~beta", flags: rpmSenseLess}, headerDependency{version: "1.0", flags: rpmSenseEqual}, true, true, "rpm_constraint=unverified", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			condition, possible := rpmConstraint(tc.requirement, tc.known, rpmProvider{version: tc.offer.version, flags: tc.offer.flags, known: tc.offerKnown})
			if condition != tc.condition || possible != tc.possible {
				t.Fatalf("rpmConstraint = (%q, %t), want (%q, %t)", condition, possible, tc.condition, tc.possible)
			}
		})
	}
}
