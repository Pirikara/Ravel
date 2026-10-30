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
