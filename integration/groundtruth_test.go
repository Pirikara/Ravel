package integration_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// These expectations come from package-manager artifacts in an external
// benchmark. They are deliberately decoded without using Ravel collectors.
func TestDeepBitsGroundtruth(t *testing.T) {
	base := filepath.Join("..", "testdata", "groundtruth", "deepbits")
	for _, tc := range []struct {
		name      string
		input     string
		gold      func(string) (map[string]int, error)
		checkEdge bool
	}{
		{"composer-install", "composer/composer.lock", composerInstallGold, true},
		{"npm-lock", "npm/package-lock.json", npmLockGold, false},
		{"cargo-lock", "cargo/Cargo.lock", cargoLockGold, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(base, tc.input)
			want, err := tc.gold(filepath.Dir(input))
			if err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "sbom.json")
			cmd := exec.Command(executable, "scan", input, "--format", "ravel-json", "--output", output)
			if data, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("scan failed: %v: %s", err, data)
			}
			var got struct {
				Components []struct {
					ID, Kind, Name, Version string
				}
				Edges []struct {
					From, To, Kind string
				}
				Origins []struct {
					Occurrence, Kind, SafeURL string
				}
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			actual := make(map[string]int)
			byID := make(map[string]string)
			componentByID := make(map[string]struct{ Name, Version string })
			for _, p := range got.Components {
				if p.Kind != "package" && p.Kind != "application" {
					continue
				}
				key := packageKey(p.Name, p.Version)
				actual[key]++
				byID[p.ID] = p.Name
				componentByID[p.ID] = struct{ Name, Version string }{p.Name, p.Version}
			}
			compareGold(t, "package name/version", want, actual)
			if tc.checkEdge {
				wantedEdges, err := composerEdgeGold(filepath.Dir(input))
				if err != nil {
					t.Fatal(err)
				}
				actualEdges := make(map[string]int)
				for _, edge := range got.Edges {
					from, hasFrom := byID[edge.From]
					to, hasTo := byID[edge.To]
					if edge.Kind == "depends_on" && hasFrom && hasTo {
						actualEdges[from+" -> "+to]++
					}
				}
				compareGold(t, "installed dependency edge", wantedEdges, actualEdges)
			}
			if tc.name == "composer-install" || tc.name == "npm-lock" {
				var wantedOrigins map[string]int
				if tc.name == "composer-install" {
					wantedOrigins, err = composerOriginGold(filepath.Dir(input))
				} else {
					wantedOrigins, err = npmRegistryOriginGold(filepath.Dir(input))
				}
				if err != nil {
					t.Fatal(err)
				}
				actualOrigins := make(map[string]int)
				for _, origin := range got.Origins {
					if tc.name == "npm-lock" && !strings.HasPrefix(origin.SafeURL, "https://registry.npmjs.org/") {
						continue
					}
					component := componentByID[origin.Occurrence]
					actualOrigins[originKey(component.Name, component.Version, origin.Kind, origin.SafeURL)]++
				}
				compareGold(t, "declared origin", wantedOrigins, actualOrigins)
			}
		})
	}
}

func packageKey(name, version string) string { return name + "@" + version }

func originKey(name, version, kind, locator string) string {
	return packageKey(name, version) + " " + kind + " " + locator
}

func compareGold(t *testing.T, label string, want, got map[string]int) {
	t.Helper()
	var missing, extra []string
	matched, expected, emitted := 0, 0, 0
	for key, count := range want {
		expected += count
		n := min(count, got[key])
		matched += n
		for range count - n {
			missing = append(missing, key)
		}
	}
	for key, count := range got {
		emitted += count
		for range count - min(count, want[key]) {
			extra = append(extra, key)
		}
	}
	precision, recall := 0.0, 0.0
	if expected == 0 && emitted == 0 {
		precision, recall = 1, 1
	}
	if emitted > 0 {
		precision = float64(matched) / float64(emitted)
	}
	if expected > 0 {
		recall = float64(matched) / float64(expected)
	}
	t.Logf("%s: gold=%d emitted=%d matched=%d precision=%.3f recall=%.3f", label, expected, emitted, matched, precision, recall)
	if len(missing) != 0 || len(extra) != 0 {
		slices.Sort(missing)
		slices.Sort(extra)
		t.Errorf("%s differs: missing=%s extra=%s", label, shortDifferences(missing), shortDifferences(extra))
	}
}

func shortDifferences(values []string) string {
	if len(values) > 10 {
		return fmt.Sprintf("%v (and %d more)", values[:10], len(values)-10)
	}
	return fmt.Sprint(values)
}

var composerInstallLine = regexp.MustCompile(`^  - Installing (\S+) \(([^ )]+)`)

func composerInstallGold(dir string) (map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "install.txt"))
	if err != nil {
		return nil, err
	}
	gold := make(map[string]int)
	for _, line := range strings.Split(string(data), "\n") {
		match := composerInstallLine.FindStringSubmatch(line)
		if match != nil {
			gold[packageKey(match[1], match[2])]++
		}
	}
	if len(gold) == 0 {
		return nil, fmt.Errorf("composer install record contains no packages")
	}
	return gold, nil
}

func composerEdgeGold(dir string) (map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "composer.lock"))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages []struct {
			Name    string            `json:"name"`
			Require map[string]string `json:"require"`
		} `json:"packages"`
		Dev []struct {
			Name    string            `json:"name"`
			Require map[string]string `json:"require"`
		} `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	installed := make(map[string]bool)
	for _, p := range lock.Packages {
		installed[p.Name] = true
	}
	for _, p := range lock.Dev {
		installed[p.Name] = true
	}
	gold := make(map[string]int)
	add := func(name string, requires map[string]string) {
		for dep := range requires {
			if installed[dep] {
				gold[name+" -> "+dep] = 1
			}
		}
	}
	for _, p := range lock.Packages {
		add(p.Name, p.Require)
	}
	for _, p := range lock.Dev {
		add(p.Name, p.Require)
	}
	return gold, nil
}

func npmLockGold(dir string) (map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Name, Version string
		}
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	gold := make(map[string]int)
	for path, p := range lock.Packages {
		if path == "" { // The root project is CycloneDX metadata, not an external package.
			continue
		}
		name := p.Name
		if name == "" {
			at := strings.LastIndex(path, "node_modules/")
			if at < 0 {
				return nil, fmt.Errorf("unexpected npm package location %q", path)
			}
			name = path[at+len("node_modules/"):]
		}
		gold[packageKey(name, p.Version)]++
	}
	return gold, nil
}

func cargoLockGold(dir string) (map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.lock"))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Package []struct {
			Name, Version, Source string
		} `toml:"package"`
	}
	if err := toml.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	gold := make(map[string]int)
	for _, p := range lock.Package {
		if p.Source == "" { // Local root belongs to document metadata, not the external package set.
			continue
		}
		gold[packageKey(p.Name, p.Version)]++
	}
	return gold, nil
}

func composerOriginGold(dir string) (map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "composer.lock"))
	if err != nil {
		return nil, err
	}
	type source struct{ URL string }
	type pkg struct {
		Name, Version string
		Dist          source
		Source        source
	}
	var lock struct {
		Packages []pkg
		Dev      []pkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	gold := make(map[string]int)
	for _, p := range append(lock.Packages, lock.Dev...) {
		if p.Dist.URL != "" {
			gold[originKey(p.Name, p.Version, "download_url", p.Dist.URL)]++
		}
		if p.Source.URL != "" {
			gold[originKey(p.Name, p.Version, "vcs", p.Source.URL)]++
		}
	}
	return gold, nil
}

func npmRegistryOriginGold(dir string) (map[string]int, error) {
	data, err := os.ReadFile(filepath.Join(dir, "package-lock.json"))
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Name, Version, Resolved string
		}
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	gold := make(map[string]int)
	for location, p := range lock.Packages {
		if location == "" || p.Resolved == "" {
			continue
		}
		u, err := url.Parse(p.Resolved)
		if err != nil || u.Scheme != "https" || u.Host != "registry.npmjs.org" {
			continue
		}
		u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
		name := p.Name
		if name == "" {
			name = location[strings.LastIndex(location, "node_modules/")+len("node_modules/"):]
		}
		gold[originKey(name, p.Version, "download_url", u.String())]++
	}
	return gold, nil
}
