package rpm

import "testing"

func TestParseSimpleRPMIf(t *testing.T) {
	consequence, guard, ok := parseSimpleRPMIf("(glibc-gconv-extra(aarch-64) = 2.41-16.fc42 if redhat-rpm-config)")
	if !ok || consequence.name != "glibc-gconv-extra(aarch-64)" || consequence.version != "2.41-16.fc42" || consequence.flags != rpmSenseEqual || guard.name != "redhat-rpm-config" || guard.version != "" {
		t.Fatalf("RPM implication was not parsed: consequence=%#v guard=%#v ok=%t", consequence, guard, ok)
	}
	for _, expression := range []string{
		"(a or b)", "(a if b else c)", "((a and c) if b)",
		"(a if /usr/bin/b)", "(a if rpmlib(Foo))", "(a if user(foo))",
		"(a if gpg-pubkey)", "(a if b))",
		"(a >= invalid:version if b)",
	} {
		if _, _, ok := parseSimpleRPMIf(expression); ok {
			t.Fatalf("unsupported RPM expression accepted: %q", expression)
		}
	}
}

func TestEvaluateRPMGuard(t *testing.T) {
	providers := map[string][]rpmProvider{
		"trigger": {{ref: "provider", version: "1.0-1", flags: rpmSenseEqual, known: true}},
	}
	for _, tc := range []struct {
		name, version string
		flags         uint32
		complete      bool
		want          rpmGuardState
	}{
		{"trigger", "1.0", rpmSenseGreater | rpmSenseEqual, true, rpmGuardPresent},
		{"trigger", "2.0", rpmSenseGreater | rpmSenseEqual, true, rpmGuardAbsent},
		{"missing", "", 0, true, rpmGuardAbsent},
		{"missing", "", 0, false, rpmGuardUnknown},
	} {
		guard := headerDependency{name: tc.name, version: tc.version, flags: tc.flags}
		if got := evaluateRPMGuard(guard, true, tc.complete, providers); got != tc.want {
			t.Errorf("guard %#v (complete=%t) = %d, want %d", guard, tc.complete, got, tc.want)
		}
	}
	unknown := map[string][]rpmProvider{"trigger": {{ref: "provider"}}}
	if got := evaluateRPMGuard(headerDependency{name: "trigger", version: "1.0", flags: rpmSenseEqual}, true, true, unknown); got != rpmGuardUnknown {
		t.Fatalf("unknown provider version settled RPM guard: %d", got)
	}
}
