package gomod

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedResolverOutput(t *testing.T) {
	buffer := &boundedBuffer{limit: 4}
	if n, err := buffer.Write([]byte("1234")); err != nil || n != 4 {
		t.Fatalf("short resolver output rejected: %d, %v", n, err)
	}
	if _, err := buffer.Write([]byte("5")); err == nil || !buffer.exceeded || buffer.buffer.String() != "1234" {
		t.Fatal("resolver output limit was not enforced")
	}
}

func TestGoResolverDoesNotEchoToolStderr(t *testing.T) {
	project := t.TempDir()
	mod := filepath.Join(project, "go.mod")
	if err := os.WriteFile(mod, []byte("module example.com/app\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	goTool := filepath.Join(bin, "go")
	if err := os.WriteFile(goTool, []byte("#!/bin/sh\necho 'https://user:secret@example.test/repo?token=secret' >&2\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := CollectResolved(mod, "app", false)
	if err == nil || !strings.Contains(err.Error(), "exit code 7") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("resolver error leaked stderr or lost exit status: %v", err)
	}
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		t.Fatalf("fake go tool was not executed: %v", err)
	}
}

func TestGoResolverDoesNotEchoJSONModuleError(t *testing.T) {
	project := t.TempDir()
	mod := filepath.Join(project, "go.mod")
	if err := os.WriteFile(mod, []byte("module example.com/app\n\ngo 1.23\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	goTool := filepath.Join(bin, "go")
	script := "#!/bin/sh\nprintf '%s\\n' '{\"Path\":\"example.com/dependency\",\"Version\":\"v1.0.0\",\"Error\":{\"Err\":\"https://user:secret@example.test/repo?token=secret\"}}'\n"
	if err := os.WriteFile(goTool, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := CollectResolved(mod, "app", false)
	if err == nil || !strings.Contains(err.Error(), "unresolved module") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("resolver JSON error leaked credentials: %v", err)
	}
}

func TestGoResolverReportsCasePreservingPURLCompatibility(t *testing.T) {
	project := t.TempDir()
	mod := filepath.Join(project, "go.mod")
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "fixtures", "go-purl-case-coverage", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mod, data, 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	script := `#!/bin/sh
cat <<'RAVEL_MODULES'
{"Path":"example.com/SourceApp","Main":true}
{"Path":"example.com/Acme/Lib","Version":"v1.0.0"}
{"Path":"example.net/library","Version":"v1.0.0"}
{"Path":"example.com/LOCAL","Version":"v1.0.0","Replace":{"Path":"./local"}}
{"Path":"example.com/Fork","Version":"v1.0.0","Replace":{"Path":"fork.example/Actual","Version":"v1.1.0"}}
RAVEL_MODULES
`
	if err := os.WriteFile(filepath.Join(bin, "go"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	doc, err := CollectResolved(mod, "case-app", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 5 || len(doc.Edges) != 5 {
		t.Fatal(doc.Components, doc.Edges)
	}
	wanted := map[string]bool{"example.com/SourceApp": true, "example.com/Acme/Lib": true}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code != "go_module_purl_case_preserved" {
			continue
		}
		if !wanted[issue.Name] || issue.Scope == "" {
			t.Fatal("unexpected or unlocated PURL issue", issue)
		}
		delete(wanted, issue.Name)
	}
	if len(wanted) != 0 {
		t.Fatal("unreported PURL limitation", wanted)
	}
}
