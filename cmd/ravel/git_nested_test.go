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

func testNestedGitRepository(t *testing.T, remotes, name, child, childCommit, childURL string) (string, string) {
	t.Helper()
	source := t.TempDir()
	testGit(t, source, "init", "--quiet")
	manifest := fmt.Sprintf("module example.com/%s\n\ngo 1.22\n\nrequire example.com/%s-dep v1.0.0\n", name, name)
	if err := os.WriteFile(filepath.Join(source, "go.mod"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, source, "add", "go.mod")
	if child != "" {
		if childURL == "" {
			childURL = "../" + child + ".git"
		}
		modules := fmt.Sprintf("[submodule \"deps/%s\"]\n    path = deps/%s\n    url = %s\n", child, child, childURL)
		if err := os.WriteFile(filepath.Join(source, ".gitmodules"), []byte(modules), 0o644); err != nil {
			t.Fatal(err)
		}
		testGit(t, source, "update-index", "--add", "--cacheinfo", "160000,"+childCommit+",deps/"+child)
		testGit(t, source, "add", ".gitmodules")
	}
	testGit(t, source, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", name)
	commit := testGit(t, source, "rev-parse", "HEAD")
	bare := filepath.Join(remotes, name+".git")
	cmd := exec.Command("git", "clone", "--quiet", "--bare", source, bare)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create %s bare repository: %v: %s", name, err, output)
	}
	return commit, bare
}

func testNestedScan(t *testing.T, bare, commit string) (model.Document, []byte) {
	t.Helper()
	output := filepath.Join(t.TempDir(), "nested.json")
	remote := "file://" + filepath.ToSlash(bare)
	if code := runScan([]string{remote, "--git-ref", commit, "--all", "--recursive", "--git-submodules", "--format", "ravel-json", "--output", output}); code != 0 {
		t.Fatalf("nested submodule scan exit=%d", code)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc, data
}

func TestRemoteGitNestedPinnedSubmodules(t *testing.T) {
	remotes := t.TempDir()
	leafCommit, leafBare := testNestedGitRepository(t, remotes, "leaf", "", "", "")
	middleCommit, middleBare := testNestedGitRepository(t, remotes, "middle", "leaf", leafCommit, "")
	topCommit, topBare := testNestedGitRepository(t, remotes, "top", "middle", middleCommit, "")
	rootCommit, rootBare := testNestedGitRepository(t, remotes, "root", "top", topCommit, "")
	doc, data := testNestedScan(t, rootBare, rootCommit)
	want := []struct{ scope, commit, bare string }{
		{".", rootCommit, rootBare},
		{"deps/top", topCommit, topBare},
		{"deps/top/deps/middle", middleCommit, middleBare},
		{"deps/top/deps/middle/deps/leaf", leafCommit, leafBare},
	}
	if len(doc.Git) != len(want) {
		t.Fatalf("Git provenance count: got %d, want %d", len(doc.Git), len(want))
	}
	for i, expected := range want {
		got := doc.Git[i]
		if got.Scope != expected.scope || got.Commit != expected.commit || got.RequestedURL != "file://"+filepath.ToSlash(expected.bare) {
			t.Fatalf("Git provenance %d: %#v", i, got)
		}
		if i != 0 && !strings.Contains(string(data), "git+file://"+filepath.ToSlash(expected.bare)+"@"+expected.commit+"/go.mod") {
			t.Fatalf("stable source path missing for %s", expected.scope)
		}
	}
	if strings.Contains(string(data), "ravel-git-") {
		t.Fatal("temporary checkout path leaked")
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "git_submodule_depth_limit" || issue.Code == "git_nested_submodules_not_scanned" {
			t.Fatalf("completed nested scan reported a skipped submodule: %#v", issue)
		}
	}
	cycloneOutput := filepath.Join(t.TempDir(), "nested.cdx.json")
	if code := runScan([]string{"file://" + filepath.ToSlash(rootBare), "--git-ref", rootCommit, "--all", "--recursive", "--git-submodules", "--output", cycloneOutput}); code != 0 {
		t.Fatalf("CycloneDX nested scan exit=%d", code)
	}
	cycloneBytes, err := os.ReadFile(cycloneOutput)
	if err != nil || strings.Count(string(cycloneBytes), "ravel:gitProvenance") != len(want) {
		t.Fatalf("CycloneDX nested Git provenance: %v", err)
	}
}

func TestRemoteGitNestedSubmoduleDepthAndURLLimits(t *testing.T) {
	remotes := t.TempDir()
	lastCommit, _ := testNestedGitRepository(t, remotes, "level4", "", "", "")
	level3Commit, _ := testNestedGitRepository(t, remotes, "level3", "level4", lastCommit, "")
	level2Commit, _ := testNestedGitRepository(t, remotes, "level2", "level3", level3Commit, "")
	level1Commit, _ := testNestedGitRepository(t, remotes, "level1", "level2", level2Commit, "")
	rootCommit, rootBare := testNestedGitRepository(t, remotes, "deep-root", "level1", level1Commit, "")
	doc, data := testNestedScan(t, rootBare, rootCommit)
	if len(doc.Git) != maxGitSubmoduleDepth+1 || strings.Contains(string(data), "example.com/level4-dep") {
		t.Fatalf("depth-limited scan included an unfetched submodule: Git=%#v", doc.Git)
	}
	depthIssue := false
	for _, issue := range doc.Coverage.Issues {
		depthIssue = depthIssue || issue.Code == "git_submodule_depth_limit" && issue.Scope == "deps/level1/deps/level2/deps/level3"
	}
	if !depthIssue || doc.Coverage.GraphState != "partial" {
		t.Fatalf("depth limit not reported: %#v", doc.Coverage)
	}
	badCommit, _ := testNestedGitRepository(t, remotes, "bad-child", "level4", lastCommit, "https://elsewhere.invalid/level4.git")
	badRootCommit, badRootBare := testNestedGitRepository(t, remotes, "bad-root", "bad-child", badCommit, "")
	output := filepath.Join(t.TempDir(), "must-not-exist.json")
	if code := runScan([]string{"file://" + filepath.ToSlash(badRootBare), "--git-ref", badRootCommit, "--all", "--recursive", "--git-submodules", "--format", "ravel-json", "--output", output}); code != 1 {
		t.Fatalf("cross-host nested submodule exit=%d", code)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("unsafe nested URL left a partial output: %v", err)
	}
}

func TestRemoteGitNestedSubmoduleTotalLimit(t *testing.T) {
	remotes := t.TempDir()
	leafCommit, _ := testNestedGitRepository(t, remotes, "wide-leaf", "", "", "")
	middle := t.TempDir()
	testGit(t, middle, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(middle, "go.mod"), []byte("module example.com/wide-middle\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, middle, "add", "go.mod")
	var modules strings.Builder
	for i := 0; i < maxGitSubmodules; i++ {
		name := fmt.Sprintf("leaf-%02d", i)
		fmt.Fprintf(&modules, "[submodule \"deps/%s\"]\n    path = deps/%s\n    url = ../wide-leaf.git\n", name, name)
		testGit(t, middle, "update-index", "--add", "--cacheinfo", "160000,"+leafCommit+",deps/"+name)
	}
	if err := os.WriteFile(filepath.Join(middle, ".gitmodules"), []byte(modules.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, middle, "add", ".gitmodules")
	testGit(t, middle, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "wide middle")
	middleCommit := testGit(t, middle, "rev-parse", "HEAD")
	middleBare := filepath.Join(remotes, "wide-middle.git")
	clone := exec.Command("git", "clone", "--quiet", "--bare", middle, middleBare)
	clone.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if output, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("create wide middle bare repository: %v: %s", err, output)
	}
	rootCommit, rootBare := testNestedGitRepository(t, remotes, "wide-root", "wide-middle", middleCommit, "")
	output := filepath.Join(t.TempDir(), "must-not-exist.json")
	if code := runScan([]string{"file://" + filepath.ToSlash(rootBare), "--git-ref", rootCommit, "--all", "--recursive", "--git-submodules", "--format", "ravel-json", "--output", output}); code != 1 {
		t.Fatalf("33 submodules across levels exit=%d", code)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("total-limit failure left a partial output: %v", err)
	}
}
