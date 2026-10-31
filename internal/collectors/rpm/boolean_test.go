package rpm

import "testing"

func TestParseSimpleRPMIf(t *testing.T) {
	conditional, ok := parseSimpleRPMIf("(glibc-gconv-extra(aarch-64) = 2.41-16.fc42 if redhat-rpm-config)")
	if !ok || conditional.hasElse || conditional.consequence.name != "glibc-gconv-extra(aarch-64)" || conditional.consequence.version != "2.41-16.fc42" || conditional.consequence.flags != rpmSenseEqual || conditional.guard.name != "redhat-rpm-config" || conditional.guard.version != "" {
		t.Fatalf("RPM implication was not parsed: conditional=%#v ok=%t", conditional, ok)
	}
	conditional, ok = parseSimpleRPMIf("(ravel-fixture-extra if ravel-fixture-trigger else ravel-fixture-absent)")
	if !ok || !conditional.hasElse || conditional.consequence.name != "ravel-fixture-extra" || conditional.guard.name != "ravel-fixture-trigger" || conditional.fallback.name != "ravel-fixture-absent" {
		t.Fatalf("RPM if-else was not parsed: conditional=%#v ok=%t", conditional, ok)
	}
	for _, expression := range []string{
		"(a or b)", "(a if b else c else d)", "((a and c) if b)",
		"(a if /usr/bin/b)", "(a if rpmlib(Foo))", "(a if user(foo))",
		"(a if gpg-pubkey)", "(a if b))",
		"(a if b else (c and d))", "(a if b else /usr/bin/c)",
		"(a >= invalid:version if b)",
	} {
		if _, ok := parseSimpleRPMIf(expression); ok {
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
