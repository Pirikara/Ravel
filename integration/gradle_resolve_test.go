package integration_test

import (
	"archive/zip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func TestGradleResolverWithRealMultiProject(t *testing.T) {
	if _, err := exec.LookPath("gradle"); err != nil {
		t.Skip("Gradle is not installed")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("Java is not installed")
	}
	project := t.TempDir()
	for _, dir := range []string{"app", "lib"} {
		if err := os.Mkdir(filepath.Join(project, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := map[string]string{
		"settings.gradle":  "rootProject.name = 'ravel-multi'\ninclude 'app', 'lib'\n",
		"build.gradle":     "\n",
		"app/build.gradle": "plugins { id 'java' }\nrepositories { maven { url = uri('../repo') } }\ndependencies { implementation project(':lib'); implementation 'org.example:app-dep:1.0' }\n",
		"lib/build.gradle": "plugins { id 'java' }\nrepositories { maven { url = uri('../repo') } }\ndependencies { implementation 'org.example:lib-dep:2.0' }\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(project, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, pkg := range []struct{ name, version string }{{"app-dep", "1.0"}, {"lib-dep", "2.0"}} {
		dir := filepath.Join(project, "repo", "org", "example", pkg.name, pkg.version)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		base := pkg.name + "-" + pkg.version
		pom := `<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>` + pkg.name + `</artifactId><version>` + pkg.version + `</version></project>`
		if err := os.WriteFile(filepath.Join(dir, base+".pom"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}
		jar, err := os.Create(filepath.Join(dir, base+".jar"))
		if err != nil {
			t.Fatal(err)
		}
		writer := zip.NewWriter(jar)
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := jar.Close(); err != nil {
			t.Fatal(err)
		}
	}
	result := filepath.Join(t.TempDir(), "gradle.ravel.json")
	if output, code := mavenScan(t, project, "--manager", "gradle", "--resolve", "--allow-exec", "--network", "deny", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("multi-project Gradle resolution failed, code=%d output=%s", code, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 6 || doc.Coverage.Edges != 6 || doc.Coverage.GraphState != "complete_for_scope" || doc.Coverage.OriginState != "partial" {
		t.Fatalf("unexpected multi-project Gradle coverage: %+v", doc.Coverage)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name+"|"+component.Context] = component.ID
		if component.PURL != "" {
			t.Fatalf("Gradle package without observed repository acquired a PURL: %+v", component)
		}
	}
	app := ids[":app|configuration=runtimeClasspath;project=:app"]
	appLib := ids[":lib|configuration=runtimeClasspath;project=:app"]
	lib := ids[":lib|configuration=runtimeClasspath;project=:lib"]
	appDep := ids["org.example:app-dep|configuration=runtimeClasspath;project=:app"]
	appLibDep := ids["org.example:lib-dep|configuration=runtimeClasspath;project=:app"]
	libDep := ids["org.example:lib-dep|configuration=runtimeClasspath;project=:lib"]
	if app == "" || appLib == "" || lib == "" || appDep == "" || appLibDep == "" || libDep == "" {
		t.Fatalf("missing Gradle project or package scope: %+v", ids)
	}
	connected := map[string]bool{}
	for _, edge := range doc.Edges {
		connected[edge.From+"->"+edge.To] = true
	}
	for _, pair := range [][2]string{{"root", app}, {"root", lib}, {app, appLib}, {app, appDep}, {appLib, appLibDep}, {lib, libDep}} {
		if !connected[pair[0]+"->"+pair[1]] {
			t.Fatalf("Gradle multi-project edge missing: %s -> %s", pair[0], pair[1])
		}
	}
}

const gradleGraph = `{"root":"project :","configuration":"runtimeClasspath","nodes":[{"id":"project :","kind":"project","name":":","dependencies":["org.example:alpha:1"],"failed":0,"variantCount":1},{"id":"org.example:alpha:1","kind":"module","group":"org.example","name":"alpha","version":"1","dependencies":["org.example:beta:2"],"failed":0,"variantCount":1},{"id":"org.example:beta:2","kind":"module","group":"org.example","name":"beta","version":"2","dependencies":[],"failed":0,"variantCount":1}]}`

func fakeGradle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
printf '%s\n' "$@" > "$RAVEL_GRADLE_TEST_LOG"
if [ "$RAVEL_GRADLE_TEST_FAIL" = 1 ]; then
  echo 'secret-token-from-gradle' >&2
  exit 7
fi
for arg do
  case "$arg" in
    -Dravel.output=*) graph=${arg#-Dravel.output=} ;;
  esac
done
if [ -z "$graph" ]; then exit 8; fi
printf '%s' "$RAVEL_GRADLE_TEST_GRAPH" > "$graph"
`
	if err := os.WriteFile(filepath.Join(dir, "gradle"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGradleResolverOptInAndSelection(t *testing.T) {
	project := t.TempDir()
	build := filepath.Join(project, "build.gradle.kts")
	buildData := []byte(`plugins { java }`)
	if err := os.WriteFile(build, buildData, 0o644); err != nil {
		t.Fatal(err)
	}
	toolsDir := fakeGradle(t)
	log := filepath.Join(t.TempDir(), "args")
	t.Setenv("PATH", toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RAVEL_GRADLE_TEST_LOG", log)
	t.Setenv("RAVEL_GRADLE_TEST_GRAPH", gradleGraph)
	if output, code := mavenScan(t, project); code != 2 || !strings.Contains(string(output), "--resolve --allow-exec") {
		t.Fatalf("expected static Gradle refusal, code=%d output=%s", code, output)
	}
	if output, code := mavenScan(t, project, "--resolve"); code != 2 || !strings.Contains(string(output), "--allow-exec") {
		t.Fatalf("expected execution opt-in refusal, code=%d output=%s", code, output)
	}
	result := filepath.Join(t.TempDir(), "gradle.json")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("Gradle resolver failed, code=%d output=%s", code, output)
	}
	args, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--no-daemon", "--no-configuration-cache", "--init-script", "-Dravel.configuration=runtimeClasspath", "--offline", "ravelSbomGraph"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("Gradle args omitted %s: %s", want, args)
		}
	}
	var doc model.Document
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Source != build || doc.Coverage.Manager != "gradle" || doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.GraphState != "complete_for_scope" {
		t.Fatalf("unexpected Gradle graph: %#v", doc)
	}
	for _, component := range doc.Components {
		if component.PURL != "" {
			t.Fatalf("Gradle module without observed repository was assigned Maven Central PURL: %s", component.PURL)
		}
	}
	actualBuild, err := os.ReadFile(build)
	if err != nil || string(actualBuild) != string(buildData) {
		t.Fatalf("build file changed: %v", err)
	}
	lock := filepath.Join(project, "gradle.lockfile")
	if err := os.WriteFile(lock, []byte("org.example:static:9=runtimeClasspath\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, code := mavenScan(t, project, "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("Gradle lockfile scan failed, code=%d output=%s", code, output)
	}
	data, _ = os.ReadFile(result)
	if err := json.Unmarshal(data, &doc); err != nil || doc.Components[0].Name != "org.example:static" {
		t.Fatalf("Gradle lockfile not preferred: %v %#v", err, doc.Components)
	}
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("Gradle resolver with lockfile failed, code=%d output=%s", code, output)
	}
	data, _ = os.ReadFile(result)
	if err := json.Unmarshal(data, &doc); err != nil || doc.Coverage.Packages != 2 {
		t.Fatalf("Gradle resolver not preferred: %v %#v", err, doc.Coverage)
	}
	if output, code := mavenScan(t, project, "--output", build); code != 2 || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("build file overwrite not blocked, code=%d output=%s", code, output)
	}
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--output", lock); code != 2 || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("lockfile overwrite not blocked, code=%d output=%s", code, output)
	}
}

func TestGradleResolverConfigurationAndFailure(t *testing.T) {
	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, "build.gradle"), []byte("plugins { id 'java' }"), 0o644); err != nil {
		t.Fatal(err)
	}
	toolsDir := fakeGradle(t)
	t.Setenv("PATH", toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	log := filepath.Join(t.TempDir(), "args")
	t.Setenv("RAVEL_GRADLE_TEST_LOG", log)
	t.Setenv("RAVEL_GRADLE_TEST_GRAPH", strings.Replace(gradleGraph, "runtimeClasspath", "testRuntimeClasspath", 1))
	result := filepath.Join(t.TempDir(), "gradle.json")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--configuration", "testRuntimeClasspath", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("custom configuration failed, code=%d output=%s", code, output)
	}
	args, _ := os.ReadFile(log)
	if !strings.Contains(string(args), "-Dravel.configuration=testRuntimeClasspath") {
		t.Fatalf("configuration not passed to Gradle: %s", args)
	}
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--configuration", "bad name"); code != 1 || !strings.Contains(string(output), "invalid Gradle configuration") {
		t.Fatalf("invalid configuration accepted, code=%d output=%s", code, output)
	}
	t.Setenv("RAVEL_GRADLE_TEST_FAIL", "1")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec"); code != 1 || strings.Contains(string(output), "secret-token") || !strings.Contains(string(output), "exit code 7") {
		t.Fatalf("Gradle failure leaked stderr or lost exit code, code=%d output=%s", code, output)
	}
}

func TestGradleResolverWithRealGradle(t *testing.T) {
	if _, err := exec.LookPath("gradle"); err != nil {
		t.Skip("Gradle is not installed")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("Java is not installed")
	}
	project := t.TempDir()
	build := `plugins { id 'java' }
repositories { maven { url = uri('repo') } }
dependencies { implementation 'org.example:alpha:1.0' }
`
	if err := os.WriteFile(filepath.Join(project, "build.gradle"), []byte(build), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, module := range []struct {
		name string
		deps string
	}{
		{"alpha", `<dependencies><dependency><groupId>org.example</groupId><artifactId>beta</artifactId><version>2.0</version></dependency></dependencies>`},
		{"beta", ""},
	} {
		version := "1.0"
		if module.name == "beta" {
			version = "2.0"
		}
		dir := filepath.Join(project, "repo", "org", "example", module.name, version)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		pom := `<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>` + module.name + `</artifactId><version>` + version + `</version>` + module.deps + `</project>`
		if err := os.WriteFile(filepath.Join(dir, module.name+"-"+version+".pom"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result := filepath.Join(t.TempDir(), "gradle.json")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("real Gradle resolution failed, code=%d output=%s", code, output)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 2 || doc.Coverage.Edges != 2 || doc.Coverage.GraphState != "complete_for_scope" {
		t.Fatalf("real Gradle graph incorrect: %#v", doc)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
	}
	if ids["org.example:alpha"] == "" || ids["org.example:beta"] == "" {
		t.Fatalf("real Gradle packages missing: %#v", doc.Components)
	}
	var rootToAlpha, alphaToBeta bool
	for _, edge := range doc.Edges {
		rootToAlpha = rootToAlpha || edge.From == "root" && edge.To == ids["org.example:alpha"]
		alphaToBeta = alphaToBeta || edge.From == ids["org.example:alpha"] && edge.To == ids["org.example:beta"]
	}
	if !rootToAlpha || !alphaToBeta {
		t.Fatalf("real Gradle dependency edges missing: %#v", doc.Edges)
	}
}
