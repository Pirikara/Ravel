package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/model"
)

func testGitLFSPointer() string {
	return "version https://git-lfs.github.com/spec/v1\n" +
		"oid sha256:" + strings.Repeat("a", 64) + "\n" +
		"size 12345\n"
}

func TestGitLFSPointerGrammar(t *testing.T) {
	valid := testGitLFSPointer()
	if !isGitLFSPointer([]byte(valid)) {
		t.Fatal("valid Git LFS pointer was missed")
	}
	for _, content := range []string{
		strings.TrimSuffix(valid, "\n"),
		strings.Replace(valid, "sha256:", "sha1:", 1),
		strings.Replace(valid, "size 12345", "size -1", 1),
		strings.Replace(valid, "oid sha256:", "size 12345\noid sha256:", 1),
		strings.Replace(valid, "spec/v1", "spec/v2", 1),
		valid + strings.Repeat("x", 1024),
	} {
		if isGitLFSPointer([]byte(content)) {
			t.Fatalf("invalid Git LFS pointer accepted: %q", content)
		}
	}
}

func TestRemoteGitReportsUnmaterializedLFSPointer(t *testing.T) {
	source, _ := testGitRepository(t)
	if err := os.Mkdir(filepath.Join(source, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "assets", "payload.bin"), []byte(testGitLFSPointer()), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, source, "add", "assets/payload.bin")
	testGit(t, source, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "LFS pointer fixture")
	commit := testGit(t, source, "rev-parse", "HEAD")
	bare := filepath.Join(t.TempDir(), "repository.git")
	cmd := exec.Command("git", "clone", "--quiet", "--bare", source, bare)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create bare remote: %v: %s", err, output)
	}
	output := filepath.Join(t.TempDir(), "result.json")
	if code := runScan([]string{"file://" + filepath.ToSlash(bare), "--git-ref", commit, "--all", "--recursive", "--format", "ravel-json", "--output", output}); code != 0 {
		t.Fatalf("remote scan exit=%d", code)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Coverage.GraphState != "partial" {
		t.Fatalf("LFS pointer should make coverage partial: %#v", doc.Coverage)
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "git_lfs_pointer_not_materialized" && issue.Scope == "assets/payload.bin" {
			return
		}
	}
	t.Fatalf("LFS pointer coverage issue missing: %#v", doc.Coverage.Issues)
}

func TestGitLFSPointerReportLimit(t *testing.T) {
	root := t.TempDir()
	for i := 0; i <= maxReportedGitLFSPointers; i++ {
		name := filepath.Join(root, fmt.Sprintf("pointer-%02d", i))
		if err := os.WriteFile(name, []byte(testGitLFSPointer()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths, limited, err := gitLFSPointerPaths(root)
	if err != nil || !limited || len(paths) != maxReportedGitLFSPointers {
		t.Fatalf("pointer report limit: %d, %t, %v", len(paths), limited, err)
	}
}
