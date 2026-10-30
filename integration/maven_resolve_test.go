package integration_test

import (
	"archive/zip"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"ravel/internal/model"
)

const mavenTree = `{"groupId":"example","artifactId":"app","version":"1","type":"jar","children":[{"groupId":"resolved","artifactId":"dep","version":"2","type":"jar","scope":"compile","children":[]}]}`

func fakeMaven(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
printf '%s\n' "$@" > "$RAVEL_MAVEN_TEST_LOG"
if [ "$RAVEL_MAVEN_TEST_FAIL" = 1 ]; then
  echo 'secret-token-from-maven' >&2
  exit 7
fi
for arg do
  case "$arg" in
    -DoutputFile=*) tree=${arg#-DoutputFile=} ;;
  esac
done
if [ -z "$tree" ]; then exit 8; fi
printf '%s' "$RAVEL_MAVEN_TEST_TREE" > "$tree"
`
	if err := os.WriteFile(filepath.Join(dir, "mvn"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func mavenScan(t *testing.T, path string, args ...string) ([]byte, int) {
	t.Helper()
	cmd := exec.Command(executable, append([]string{"scan", path}, args...)...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return output, 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return output, exit.ExitCode()
	}
	t.Fatal(err)
	return nil, 0
}

func TestMavenResolverOptInAndSelection(t *testing.T) {
	project := t.TempDir()
	pom := filepath.Join(project, "pom.xml")
	pomData := []byte(`<project><modelVersion>4.0.0</modelVersion><groupId>example</groupId><artifactId>app</artifactId><version>1</version><dependencyManagement><dependencies><dependency><groupId>managed</groupId><artifactId>not-selected</artifactId><version>9</version></dependency></dependencies></dependencyManagement><dependencies><dependency><groupId>declared</groupId><artifactId>dep</artifactId><version>1</version><scope>test</scope><optional>true</optional></dependency><dependency><groupId>dynamic</groupId><artifactId>dep</artifactId><version>${v}</version></dependency></dependencies></project>`)
	if err := os.WriteFile(pom, pomData, 0o644); err != nil {
		t.Fatal(err)
	}
	toolsDir := fakeMaven(t)
	log := filepath.Join(t.TempDir(), "args")
	t.Setenv("PATH", toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RAVEL_MAVEN_TEST_LOG", log)
	t.Setenv("RAVEL_MAVEN_TEST_TREE", mavenTree)
	result := filepath.Join(t.TempDir(), "resolved.json")
	if output, code := mavenScan(t, project, "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("static pom scan failed, code=%d output=%s", code, output)
	}
	var doc model.Document
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 1 || doc.Coverage.GraphState != "partial" || doc.Components[0].Name != "declared:dep" || doc.Components[0].PURL != "" || doc.Edges[0].Condition != "scope=test && optional=true" {
		t.Fatalf("static POM overstated resolution or lost conditions: %#v", doc)
	}
	for _, component := range doc.Components {
		if component.Name == "managed:not-selected" || component.Name == "dynamic:dep" {
			t.Fatalf("unselected dependency included: %#v", component)
		}
	}
	if output, code := mavenScan(t, project, "--resolve"); code != 2 || !strings.Contains(string(output), "--allow-exec") {
		t.Fatalf("expected execution opt-in refusal, code=%d output=%s", code, output)
	}
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("resolver failed, code=%d output=%s", code, output)
	}
	args, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-B", "-N", "dependency:tree", "-DoutputType=json", "-DoutputFile=", "-o"} {
		if !strings.Contains(string(args), want) {
			t.Fatalf("Maven args omitted %s: %s", want, args)
		}
	}
	data, err = os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Source != pom || doc.Coverage.Manager != "maven" || doc.Coverage.Packages != 1 || doc.Coverage.Edges != 1 || doc.Coverage.GraphState != "complete_for_scope" {
		t.Fatalf("unexpected resolved document: %#v", doc)
	}
	if doc.Components[0].Name != "resolved:dep" || doc.Components[0].Version != "2" || doc.Components[0].PURL != "" || doc.Components[0].Evidence[0].InputPath != "mvn dependency:tree" {
		t.Fatalf("unexpected resolved package: %#v", doc.Components[0])
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "manifest_freshness_unverified" {
			t.Fatalf("fresh resolver output had stale manifest issue: %#v", doc.Coverage.Issues)
		}
	}
	actualPOM, err := os.ReadFile(pom)
	if err != nil || string(actualPOM) != string(pomData) {
		t.Fatalf("pom.xml changed: %v", err)
	}
	static := strings.Replace(mavenTree, "resolved", "static", 1)
	if err := os.WriteFile(filepath.Join(project, "dependency-tree.json"), []byte(static), 0o644); err != nil {
		t.Fatal(err)
	}
	if output, code := mavenScan(t, project, "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("static scan failed, code=%d output=%s", code, output)
	}
	data, _ = os.ReadFile(result)
	if err := json.Unmarshal(data, &doc); err != nil || doc.Components[0].Name != "static:dep" {
		t.Fatalf("static tree not preferred: %v %#v", err, doc.Components)
	}
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--network", "allow", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("network-enabled resolver failed, code=%d output=%s", code, output)
	}
	args, _ = os.ReadFile(log)
	if strings.Contains(string(args), "\n-o\n") {
		t.Fatalf("Maven was offline despite network allow: %s", args)
	}
	data, _ = os.ReadFile(result)
	if err := json.Unmarshal(data, &doc); err != nil || doc.Components[0].Name != "resolved:dep" {
		t.Fatalf("resolver not preferred: %v %#v", err, doc.Components)
	}
	if output, code := mavenScan(t, project, "--output", pom); code != 2 || !strings.Contains(string(output), "cannot overwrite") {
		t.Fatalf("pom overwrite not blocked, code=%d output=%s", code, output)
	}
}

func TestMavenResolverFailureAndRootScope(t *testing.T) {
	project := t.TempDir()
	pom := filepath.Join(project, "pom.xml")
	if err := os.WriteFile(pom, []byte(`<project><modules><module>child</module></modules></project>`), 0o644); err != nil {
		t.Fatal(err)
	}
	toolsDir := fakeMaven(t)
	t.Setenv("PATH", toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RAVEL_MAVEN_TEST_LOG", filepath.Join(t.TempDir(), "args"))
	t.Setenv("RAVEL_MAVEN_TEST_TREE", mavenTree)
	result := filepath.Join(t.TempDir(), "resolved.json")
	if output, code := mavenScan(t, pom, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result, "--strict"); code != 3 {
		t.Fatalf("expected partial multi-module scope, code=%d output=%s", code, output)
	}
	var doc model.Document
	data, _ := os.ReadFile(result)
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.GraphState != "partial" {
		t.Fatalf("multi-module graph reported complete: %#v", doc.Coverage)
	}
	found := false
	for _, issue := range doc.Coverage.Issues {
		found = found || issue.Code == "multi_module_scope_root"
	}
	if !found {
		t.Fatalf("missing multi-module issue: %#v", doc.Coverage.Issues)
	}
	t.Setenv("RAVEL_MAVEN_TEST_FAIL", "1")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec"); code != 1 || strings.Contains(string(output), "secret-token") || !strings.Contains(string(output), "exit code 7") {
		t.Fatalf("Maven failure leaked stderr or lost exit code, code=%d output=%s", code, output)
	}
}

func TestMavenResolverReactorGraph(t *testing.T) {
	project := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(project, "pom.xml"), `<project><modelVersion>4.0.0</modelVersion><groupId>org.demo</groupId><artifactId>parent</artifactId><version>1.0.0</version><packaging>pom</packaging><modules><module>api</module><module>web</module></modules></project>`)
	childHead := `<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.demo</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>`
	write(filepath.Join(project, "api", "pom.xml"), childHead+`<artifactId>api</artifactId><dependencies><dependency><groupId>org.libs</groupId><artifactId>alpha</artifactId><version>1</version></dependency></dependencies></project>`)
	write(filepath.Join(project, "web", "pom.xml"), childHead+`<artifactId>web</artifactId><dependencies><dependency><groupId>org.demo</groupId><artifactId>api</artifactId><version>1.0.0</version></dependency><dependency><groupId>org.libs</groupId><artifactId>alpha</artifactId><version>1</version></dependency><dependency><groupId>org.libs</groupId><artifactId>beta</artifactId><version>2</version></dependency></dependencies></project>`)
	treesDir := t.TempDir()
	write(filepath.Join(treesDir, "parent.json"), `{"groupId":"org.demo","artifactId":"parent","version":"1.0.0","type":"pom"}`)
	write(filepath.Join(treesDir, "api.json"), `{"groupId":"org.demo","artifactId":"api","version":"1.0.0","type":"jar","children":[{"groupId":"org.libs","artifactId":"alpha","version":"1","type":"jar","scope":"compile"}]}`)
	write(filepath.Join(treesDir, "web.json"), `{"groupId":"org.demo","artifactId":"web","version":"1.0.0","type":"jar","children":[{"groupId":"org.demo","artifactId":"api","version":"1.0.0","type":"jar","scope":"compile","children":[{"groupId":"org.libs","artifactId":"alpha","version":"1","type":"jar","scope":"compile"}]},{"groupId":"org.libs","artifactId":"alpha","version":"1","type":"jar","scope":"compile"},{"groupId":"org.libs","artifactId":"beta","version":"2","type":"jar","scope":"compile"}]}`)
	toolsDir := t.TempDir()
	script := `#!/bin/sh
printf '%s\n' "$@" > "$RAVEL_MAVEN_TEST_LOG"
for arg do
  case "$arg" in
    -DoutputFile=*) output=${arg#-DoutputFile=} ;;
  esac
done
case "$output" in
  *'${project.groupId}--${project.artifactId}--${project.version}.json') ;;
  *) exit 8 ;;
esac
for file in "$RAVEL_MAVEN_REACTOR_DIR"/*.json; do
  cp "$file" "${output%/*}/"
done
`
	write(filepath.Join(toolsDir, "mvn"), script)
	if err := os.Chmod(filepath.Join(toolsDir, "mvn"), 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "args")
	t.Setenv("PATH", toolsDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RAVEL_MAVEN_TEST_LOG", log)
	t.Setenv("RAVEL_MAVEN_REACTOR_DIR", treesDir)
	result := filepath.Join(t.TempDir(), "resolved.json")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("reactor resolution failed, code=%d output=%s", code, output)
	}
	args, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), "\n-N\n") || !strings.Contains(string(args), "\n-o\n") {
		t.Fatalf("Maven did not resolve the offline reactor: %s", args)
	}
	data, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.Packages != 5 || doc.Coverage.Edges != 6 || doc.Coverage.GraphState != "complete_for_scope" || len(doc.Origins) != 2 || len(doc.Sources) != 2 {
		t.Fatalf("reactor coverage incorrect: %#v", doc)
	}
	ids := map[string]string{}
	alphaByProject := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
		if component.Name == "org.libs:alpha" {
			alphaByProject[component.Context] = component.ID
		}
		if component.Kind == "package" && (!strings.Contains(component.Context, "project=") || !strings.HasPrefix(component.Evidence[0].InputPath, "mvn dependency:tree ")) {
			t.Fatalf("external package lost project scope or resolver evidence: %#v", component)
		}
	}
	apiAlpha := alphaByProject["project=org.demo:api;scopes=compile"]
	webAlpha := alphaByProject["project=org.demo:web;scopes=compile"]
	if ids["org.demo:api"] == "" || ids["org.demo:web"] == "" || apiAlpha == "" || webAlpha == "" || apiAlpha == webAlpha || ids["org.libs:beta"] == "" {
		t.Fatalf("reactor packages missing: %#v", doc.Components)
	}
	for _, want := range []struct{ from, to, kind string }{
		{"root", ids["org.demo:api"], "module"},
		{"root", ids["org.demo:web"], "module"},
		{ids["org.demo:api"], apiAlpha, "direct"},
		{ids["org.demo:web"], ids["org.demo:api"], "direct"},
		{ids["org.demo:web"], webAlpha, "direct"},
		{ids["org.demo:web"], ids["org.libs:beta"], "direct"},
	} {
		found := false
		for _, edge := range doc.Edges {
			found = found || edge.From == want.from && edge.To == want.to && edge.Kind == want.kind
		}
		if !found {
			t.Fatalf("missing reactor edge %+v in %#v", want, doc.Edges)
		}
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "multi_module_scope_root" || issue.Code == "transitive_graph_unavailable" || issue.Code == "maven_inherited_dependencies_unavailable" || issue.Code == "manifest_freshness_unverified" || issue.Name == "org.demo:api" && issue.Code == "missing_source" {
			t.Fatalf("reactor issue should be resolved: %#v", issue)
		}
	}
	if err := os.Remove(filepath.Join(treesDir, "api.json")); err != nil {
		t.Fatal(err)
	}
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec"); code != 1 || !strings.Contains(string(output), "expected 3") {
		t.Fatalf("missing module tree was accepted, code=%d output=%s", code, output)
	}
}

func TestMavenResolverWithRealReactor(t *testing.T) {
	if os.Getenv("RAVEL_TEST_REAL_MAVEN") != "1" {
		t.Skip("set RAVEL_TEST_REAL_MAVEN=1 to run Maven plugin integration")
	}
	if _, err := exec.LookPath("mvn"); err != nil {
		t.Skip("Maven is not installed")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("Java is not installed")
	}
	project := t.TempDir()
	root := `<project><modelVersion>4.0.0</modelVersion><groupId>org.demo</groupId><artifactId>parent</artifactId><version>1.0.0</version><packaging>pom</packaging><modules><module>api</module><module>web</module></modules><build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-dependency-plugin</artifactId><version>3.9.0</version></plugin></plugins></build></project>`
	child := `<project><modelVersion>4.0.0</modelVersion><parent><groupId>org.demo</groupId><artifactId>parent</artifactId><version>1.0.0</version></parent>`
	for path, content := range map[string]string{
		"pom.xml":     root,
		"api/pom.xml": child + `<artifactId>api</artifactId></project>`,
		"web/pom.xml": child + `<artifactId>web</artifactId><dependencies><dependency><groupId>org.demo</groupId><artifactId>api</artifactId><version>1.0.0</version></dependency></dependencies></project>`,
	} {
		file := filepath.Join(project, path)
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	result := filepath.Join(t.TempDir(), "reactor.json")
	for _, network := range []string{"allow", "deny"} {
		if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--network", network, "--format", "ravel-json", "--output", result, "--strict"); code != 0 {
			t.Fatalf("real Maven reactor resolution failed for network=%s, code=%d output=%s", network, code, output)
		}
		data, err := os.ReadFile(result)
		if err != nil {
			t.Fatal(err)
		}
		var doc model.Document
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Coverage.Packages != 2 || doc.Coverage.Edges != 3 || doc.Coverage.GraphState != "complete_for_scope" || doc.Coverage.OriginState != "complete_for_scope" {
			t.Fatalf("real reactor graph incorrect: %#v", doc)
		}
	}
}

func TestMavenResolverWithRealMaven(t *testing.T) {
	if os.Getenv("RAVEL_TEST_REAL_MAVEN") != "1" {
		t.Skip("set RAVEL_TEST_REAL_MAVEN=1 to run Maven plugin integration")
	}
	if _, err := exec.LookPath("mvn"); err != nil {
		t.Skip("Maven is not installed")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("Java is not installed")
	}
	project := t.TempDir()
	repo := filepath.Join(project, "repo")
	for _, module := range []struct {
		name, version, deps string
	}{
		{"alpha", "1.0", `<dependencies><dependency><groupId>org.example</groupId><artifactId>beta</artifactId><version>2.0</version></dependency></dependencies>`},
		{"beta", "2.0", ""},
	} {
		dir := filepath.Join(repo, "org", "example", module.name, module.version)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		base := module.name + "-" + module.version
		pom := `<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>` + module.name + `</artifactId><version>` + module.version + `</version>` + module.deps + `</project>`
		if err := os.WriteFile(filepath.Join(dir, base+".pom"), []byte(pom), 0o644); err != nil {
			t.Fatal(err)
		}
		file, err := os.Create(filepath.Join(dir, base+".jar"))
		if err != nil {
			t.Fatal(err)
		}
		writer := zip.NewWriter(file)
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	repositoryURL := (&url.URL{Scheme: "file", Path: repo}).String()
	pom := `<project><modelVersion>4.0.0</modelVersion><groupId>org.example</groupId><artifactId>app</artifactId><version>1.0</version><repositories><repository><id>ravel-test</id><url>` + repositoryURL + `</url></repository></repositories><dependencies><dependency><groupId>org.example</groupId><artifactId>alpha</artifactId><version>1.0</version></dependency></dependencies><build><plugins><plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-dependency-plugin</artifactId><version>3.9.0</version></plugin></plugins></build></project>`
	if err := os.WriteFile(filepath.Join(project, "pom.xml"), []byte(pom), 0o644); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(t.TempDir(), "maven.json")
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--network", "allow", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("real Maven resolution failed, code=%d output=%s", code, output)
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
		t.Fatalf("real Maven graph incorrect: %#v", doc)
	}
	ids := map[string]string{}
	for _, component := range doc.Components {
		ids[component.Name] = component.ID
	}
	if ids["org.example:alpha"] == "" || ids["org.example:beta"] == "" {
		t.Fatalf("real Maven packages missing: %#v", doc.Components)
	}
	var rootToAlpha, alphaToBeta bool
	for _, edge := range doc.Edges {
		rootToAlpha = rootToAlpha || edge.From == "root" && edge.To == ids["org.example:alpha"]
		alphaToBeta = alphaToBeta || edge.From == ids["org.example:alpha"] && edge.To == ids["org.example:beta"]
	}
	if !rootToAlpha || !alphaToBeta {
		t.Fatalf("real Maven dependency edges missing: %#v", doc.Edges)
	}
	if output, code := mavenScan(t, project, "--resolve", "--allow-exec", "--network", "deny", "--format", "ravel-json", "--output", result); code != 0 {
		t.Fatalf("real Maven offline resolution failed after cache warmup, code=%d output=%s", code, output)
	}
}
