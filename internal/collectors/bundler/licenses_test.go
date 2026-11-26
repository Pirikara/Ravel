package bundler

import (
	"github.com/Pirikara/Ravel/internal/licensing"
	"github.com/Pirikara/Ravel/internal/model"
	"testing"
)

func TestLiteralGemspecLicenses(t *testing.T) {
	for _, test := range []struct {
		source     string
		count      int
		unresolved bool
		expression string
	}{
		{`s.license = "MIT".freeze # metadata`, 1, false, "MIT"},
		{`s.licenses = ["MIT".freeze, 'Apache-2.0'].freeze`, 2, false, "NOASSERTION"},
		{"s.licenses = [\n 'MIT',\n 'BSD-2-Clause',\n]", 2, false, "NOASSERTION"},
		{`s.licenses = %w[MIT BSD-2-Clause]`, 2, false, "NOASSERTION"},
		{`s.licenses = compute_licenses()`, 0, true, "NOASSERTION"},
		{`s.license = "#{dynamic}"`, 0, true, "NOASSERTION"},
		{`other.license = "MIT"`, 0, false, "NOASSERTION"},
	} {
		got, unresolved := DeclaredLicenses([]byte(test.source), "s", model.Evidence{InputPath: "test.gemspec"})
		if len(got) != test.count || unresolved != test.unresolved || licensing.DeclaredExpression(got) != test.expression {
			t.Errorf("%s: %#v unresolved=%v", test.source, got, unresolved)
		}
		for _, d := range got {
			if d.Evidence[0].Line < 1 {
				t.Fatal("missing source line")
			}
		}
	}
}
