package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Pirikara/Ravel/internal/export"
	"github.com/Pirikara/Ravel/internal/model"
)

func testGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	cmd := exec.Command("git", append([]string{"-C", directory}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_TERMINAL_PROMPT=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func testGitRepository(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	testGit(t, directory, "init", "--quiet")
	manifest := filepath.Join(directory, "go.mod")
	if err := os.WriteFile(manifest, []byte("module example.com/test\n\ngo 1.22\n\nrequire example.com/library v1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, directory, "add", "go.mod")
	testGit(t, directory, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")
	return directory, testGit(t, directory, "rev-parse", "HEAD")
}

func TestLocalGitProvenance(t *testing.T) {
	repository, commit := testGitRepository(t)
	clean, err := localGitProvenance(repository)
	if err != nil || clean == nil || clean.Commit != commit || clean.Dirty || clean.Scope != "." {
		t.Fatalf("clean worktree: %#v, %v", clean, err)
	}
	output := filepath.Join(t.TempDir(), "local.json")
	if code := runScan([]string{repository, "--all", "--format", "ravel-json", "--output", output}); code != 0 {
		t.Fatalf("local repository scan exit=%d", code)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var scanned model.Document
	if err := json.Unmarshal(data, &scanned); err != nil || len(scanned.Git) != 1 || scanned.Git[0].Commit != commit || scanned.Git[0].Dirty {
		t.Fatalf("local scan Git provenance: %#v, %v", scanned.Git, err)
	}
	file, err := localGitProvenance(filepath.Join(repository, "go.mod"))
	if err != nil || file == nil || file.Scope != "go.mod" {
		t.Fatalf("single-file scope: %#v, %v", file, err)
	}
	if err := os.WriteFile(filepath.Join(repository, "go.mod"), []byte("module example.com/changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirty, err := localGitProvenance(repository)
	if err != nil || dirty == nil || !dirty.Dirty {
		t.Fatalf("dirty worktree: %#v, %v", dirty, err)
	}
	testGit(t, repository, "checkout", "--quiet", "--force", "--detach", commit)
	detached, err := localGitProvenance(repository)
	if err != nil || detached == nil || detached.Commit != commit || detached.Dirty {
		t.Fatalf("detached worktree: %#v, %v", detached, err)
	}
	plain, err := localGitProvenance(t.TempDir())
	if err != nil || plain != nil {
		t.Fatalf("exported tree should have no Git claim: %#v, %v", plain, err)
	}
	nested := filepath.Join(repository, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	testGit(t, nested, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(nested, "go.mod"), []byte("module example.com/nested\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, nested, "add", "go.mod")
	testGit(t, nested, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "nested")
	nestedCommit := testGit(t, nested, "rev-parse", "HEAD")
	nestedProvenance, err := localGitProvenance(filepath.Join(nested, "go.mod"))
	if err != nil || nestedProvenance == nil || nestedProvenance.Commit != nestedCommit || nestedProvenance.Scope != "go.mod" || nestedProvenance.Dirty {
		t.Fatalf("nested worktree: %#v, %v", nestedProvenance, err)
	}
}

func TestRemoteGitScanAtRevision(t *testing.T) {
	source, commit := testGitRepository(t)
	testGit(t, source, "branch", "-M", "main")
	testGit(t, source, "tag", "v1")
	bare := filepath.Join(t.TempDir(), "repository.git")
	cmd := exec.Command("git", "clone", "--quiet", "--bare", source, bare)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create bare remote: %v: %s", err, output)
	}
	remote := "file://" + filepath.ToSlash(bare)
	for _, ref := range []string{"refs/heads/main", "refs/tags/v1", commit} {
		t.Run(ref, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "result.json")
			progressPath := filepath.Join(t.TempDir(), "progress.txt")
			progressFile, err := os.Create(progressPath)
			if err != nil {
				t.Fatal(err)
			}
			originalStderr := os.Stderr
			var code int
			func() {
				os.Stderr = progressFile
				defer func() { os.Stderr = originalStderr }()
				code = runScan([]string{remote, "--git-ref", ref, "--all", "--recursive", "--format", "ravel-json", "--output", output})
			}()
			if err := progressFile.Close(); err != nil {
				t.Fatal(err)
			}
			progress, err := os.ReadFile(progressPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(progress), "graph=") != 1 {
				t.Fatalf("remote scan emitted duplicate progress: %s", progress)
			}
			if code != 0 {
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
			if len(doc.Git) != 1 || doc.Git[0].Commit != commit || doc.Git[0].Dirty || doc.Git[0].RequestedRef != ref || doc.Git[0].RequestedURL != remote || doc.Coverage.Packages == 0 {
				t.Fatalf("remote provenance or packages incorrect: %#v", doc)
			}
			if doc.Project != "repository" {
				t.Fatalf("remote project identity is temporary checkout: project=%q inputs=%#v", doc.Project, doc.Coverage.Inputs)
			}
			if strings.Contains(string(data), "ravel-git-") || !strings.Contains(doc.Source, "git+"+remote+"@"+commit) {
				t.Fatalf("temporary checkout path leaked or stable source missing: %s", doc.Source)
			}
		})
	}
	invalid := filepath.Join(t.TempDir(), "invalid.json")
	temporaryRoot := t.TempDir()
	t.Setenv("TMPDIR", temporaryRoot)
	if code := runScan([]string{remote, "--git-ref", "missing", "--all", "--output", invalid}); code != 1 {
		t.Fatalf("invalid ref exit=%d", code)
	}
	if _, err := os.Stat(invalid); !os.IsNotExist(err) {
		t.Fatalf("invalid ref left an output: %v", err)
	}
	if entries, err := os.ReadDir(temporaryRoot); err != nil || len(entries) != 0 {
		t.Fatalf("invalid ref left temporary checkout artifacts: %v, %v", entries, err)
	}
	if code := runScan([]string{"https://example.invalid/repo.git", "--git-ref", "main", "--all"}); code != 2 {
		t.Fatalf("HTTPS remote without --network allow exit=%d", code)
	}
}

func TestRewriteGitPathsUsesRemoteProject(t *testing.T) {
	doc := model.Document{Project: "repository", Coverage: model.Coverage{Inputs: []model.InputCoverage{{Project: "checkout", Source: "/tmp/checkout/go.mod"}}}}
	rewriteGitPaths(&doc, "/tmp/checkout", "git+https://example.invalid/repository.git@"+strings.Repeat("a", 40))
	if doc.Coverage.Inputs[0].Project != "repository" || strings.Contains(doc.Coverage.Inputs[0].Source, "/tmp/checkout") {
		t.Fatalf("temporary checkout identity remained: %#v", doc.Coverage.Inputs[0])
	}
}

func TestRemoteGitInputAndSizeLimits(t *testing.T) {
	for _, raw := range []string{
		"http://example.com/repo.git", "https://user:secret@example.com/repo.git", "https://example.com/repo.git?token=x", "https://example.com/repo.git#main",
		"ssh://git:secret@example.com/repo.git", "ssh://-oProxyCommand=sh/repo.git", "ssh://git@example.com:99999/repo.git", "ssh://git@example.com/repo;touch-pwned.git",
	} {
		if _, err := validateGitURL(raw); err == nil {
			t.Fatalf("unsafe remote URL accepted: %s", raw)
		}
	}
	root := t.TempDir()
	file := filepath.Join(root, "oversized")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(file, maxRemoteGitBytes+1); err != nil {
		t.Fatal(err)
	}
	if err := checkRemoteGitSize(root); err == nil {
		t.Fatal("oversized checkout was accepted")
	}
}

func TestRemoteGitSSHWithConfiguredAuthentication(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SSH transport fixture requires a shell")
	}
	source, commit := testGitRepository(t)
	testGit(t, source, "branch", "-M", "main")
	bare := filepath.Join(t.TempDir(), "repository.git")
	cmd := exec.Command("git", "clone", "--quiet", "--bare", source, bare)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create bare remote: %v: %s", err, output)
	}
	bin := t.TempDir()
	sshLog := filepath.Join(t.TempDir(), "ssh-args")
	ssh := filepath.Join(bin, "ssh")
	script := "#!/bin/sh\nfor arg do last=\"$arg\"; done\nprintf '%s\\n' \"$@\" >> \"$RAVEL_SSH_LOG\"\nexec /bin/sh -c \"$last\"\n"
	if err := os.WriteFile(ssh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("RAVEL_SSH_LOG", sshLog)
	t.Setenv("GIT_SSH_COMMAND", "false") // Ravel must enforce its own noninteractive SSH options.
	remote := "ssh://git@example.invalid" + filepath.ToSlash(bare)
	output := filepath.Join(t.TempDir(), "result.json")
	if code := runScan([]string{remote, "--git-ref", "main", "--network", "allow", "--all", "--format", "ravel-json", "--output", output}); code != 0 {
		t.Fatalf("SSH remote scan exit=%d", code)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Git) != 1 || doc.Git[0].Commit != commit || doc.Git[0].RequestedURL != remote || !strings.Contains(doc.Source, "git+"+remote+"@"+commit) {
		t.Fatalf("SSH provenance or source incorrect: %#v %s", doc.Git, doc.Source)
	}
	sshArgs, err := os.ReadFile(sshLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"BatchMode=yes", "StrictHostKeyChecking=yes", "ConnectTimeout=15"} {
		if !strings.Contains(string(sshArgs), required) {
			t.Fatalf("SSH option %q missing: %s", required, sshArgs)
		}
	}
	if code := runScan([]string{remote, "--git-ref", "main", "--all", "--output", filepath.Join(t.TempDir(), "denied.json")}); code != 2 {
		t.Fatalf("SSH URL without --network allow exit=%d", code)
	}
}

func TestGitProvenanceExports(t *testing.T) {
	doc := model.Document{SchemaVersion: "0.1", Project: "example", Git: []model.GitProvenance{{Commit: strings.Repeat("a", 40), Dirty: true, Scope: "subproject"}}}
	cyclone, err := export.CycloneDX(doc)
	if err != nil || !strings.Contains(string(cyclone), "ravel:gitProvenance") || !strings.Contains(string(cyclone), "subproject") {
		t.Fatalf("CycloneDX Git provenance: %s, %v", cyclone, err)
	}
	spdx, err := export.SPDX23(doc)
	if err != nil || !strings.Contains(string(spdx), "Ravel Git commit:") || !strings.Contains(string(spdx), "dirty worktree") {
		t.Fatalf("SPDX Git provenance: %s, %v", spdx, err)
	}
}

func TestRemoteGitRejectsEscapingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink fixture requires Unix")
	}
	source, _ := testGitRepository(t)
	if err := os.Symlink("../../outside", filepath.Join(source, "escape")); err != nil {
		t.Fatal(err)
	}
	testGit(t, source, "add", "escape")
	testGit(t, source, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "symlink")
	bare := filepath.Join(t.TempDir(), "symlink.git")
	cmd := exec.Command("git", "clone", "--quiet", "--bare", source, bare)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create bare remote: %v: %s", err, output)
	}
	output := filepath.Join(t.TempDir(), "should-not-exist.json")
	if code := runScan([]string{"file://" + filepath.ToSlash(bare), "--git-ref", testGit(t, source, "rev-parse", "HEAD"), "--all", "--output", output}); code != 1 {
		t.Fatalf("escaping symlink scan exit=%d", code)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("escaping symlink left an output: %v", err)
	}
}

func TestRemoteGitPinnedFirstLevelSubmodule(t *testing.T) {
	child := t.TempDir()
	testGit(t, child, "init", "--quiet")
	if err := os.WriteFile(filepath.Join(child, "go.mod"), []byte("module example.com/child\n\ngo 1.22\n\nrequire example.com/child-dep v1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, child, "add", "go.mod")
	testGit(t, child, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "child")
	childCommit := testGit(t, child, "rev-parse", "HEAD")
	remotes := t.TempDir()
	childBare := filepath.Join(remotes, "child.git")
	if output, err := exec.Command("git", "clone", "--quiet", "--bare", child, childBare).CombinedOutput(); err != nil {
		t.Fatalf("create child bare repository: %v: %s", err, output)
	}
	parent, _ := testGitRepository(t)
	modules := "[submodule \"deps/child\"]\n    path = deps/child\n    url = ../child.git\n"
	if err := os.WriteFile(filepath.Join(parent, ".gitmodules"), []byte(modules), 0o644); err != nil {
		t.Fatal(err)
	}
	testGit(t, parent, "update-index", "--add", "--cacheinfo", "160000,"+childCommit+",deps/child")
	testGit(t, parent, "add", ".gitmodules")
	testGit(t, parent, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "pin child")
	parentBare := filepath.Join(remotes, "parent.git")
	if output, err := exec.Command("git", "clone", "--quiet", "--bare", parent, parentBare).CombinedOutput(); err != nil {
		t.Fatalf("create parent bare repository: %v: %s", err, output)
	}
	remote := "file://" + filepath.ToSlash(parentBare)
	output := filepath.Join(t.TempDir(), "result.json")
	if code := runScan([]string{remote, "--git-ref", testGit(t, parent, "rev-parse", "HEAD"), "--all", "--recursive", "--git-submodules", "--format", "ravel-json", "--output", output}); code != 0 {
		t.Fatalf("submodule scan exit=%d", code)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var doc model.Document
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Git) != 2 || doc.Git[1].Commit != childCommit || doc.Git[1].Scope != "deps/child" || doc.Git[1].RequestedURL != "file://"+filepath.ToSlash(childBare) {
		t.Fatalf("submodule provenance missing: %#v", doc.Git)
	}
	stableChild := "git+file://" + filepath.ToSlash(childBare) + "@" + childCommit
	if !strings.Contains(string(data), stableChild+"/go.mod") || strings.Contains(string(data), "ravel-git-") {
		t.Fatalf("submodule evidence path missing or temporary path leaked")
	}
	for _, issue := range doc.Coverage.Issues {
		if issue.Code == "git_submodules_not_scanned" {
			t.Fatal("fetched submodule reported as skipped")
		}
	}
	cycloneOutput := filepath.Join(t.TempDir(), "submodules.cdx.json")
	if code := runScan([]string{remote, "--git-ref", testGit(t, parent, "rev-parse", "HEAD"), "--all", "--recursive", "--git-submodules", "--output", cycloneOutput}); code != 0 {
		t.Fatalf("CycloneDX submodule scan exit=%d", code)
	}
	cycloneBytes, err := os.ReadFile(cycloneOutput)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(cycloneBytes), "ravel:gitProvenance") != 2 {
		t.Fatal("CycloneDX did not preserve parent and submodule Git provenance")
	}
	skippedOutput := filepath.Join(t.TempDir(), "without-submodules.json")
	if code := runScan([]string{remote, "--git-ref", testGit(t, parent, "rev-parse", "HEAD"), "--all", "--recursive", "--format", "ravel-json", "--output", skippedOutput}); code != 0 {
		t.Fatalf("default submodule scan exit=%d", code)
	}
	skippedBytes, err := os.ReadFile(skippedOutput)
	if err != nil {
		t.Fatal(err)
	}
	var skipped model.Document
	if err := json.Unmarshal(skippedBytes, &skipped); err != nil {
		t.Fatal(err)
	}
	foundSkippedIssue := false
	for _, issue := range skipped.Coverage.Issues {
		foundSkippedIssue = foundSkippedIssue || issue.Code == "git_submodules_not_scanned"
	}
	if len(skipped.Git) != 1 || !foundSkippedIssue || strings.Contains(string(skippedBytes), "example.com/child-dep") {
		t.Fatalf("default scan unexpectedly included submodule: Git=%#v issues=%#v", skipped.Git, skipped.Coverage.Issues)
	}
	if code := runScan([]string{remote, "--git-ref", "HEAD", "--all", "--git-submodules", "--output", filepath.Join(t.TempDir(), "invalid.json")}); code != 2 {
		t.Fatalf("submodule flag without --recursive exit=%d", code)
	}
	testGit(t, parent, "update-index", "--add", "--cacheinfo", "160000,"+childCommit+",deps/unlisted")
	testGit(t, parent, "-c", "user.name=Ravel Test", "-c", "user.email=ravel@example.invalid", "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "unlisted gitlink")
	unlistedBare := filepath.Join(remotes, "parent-unlisted.git")
	if output, err := exec.Command("git", "clone", "--quiet", "--bare", parent, unlistedBare).CombinedOutput(); err != nil {
		t.Fatalf("create unlisted parent repository: %v: %s", err, output)
	}
	unlistedOutput := filepath.Join(t.TempDir(), "must-not-exist.json")
	if code := runScan([]string{"file://" + filepath.ToSlash(unlistedBare), "--git-ref", testGit(t, parent, "rev-parse", "HEAD"), "--all", "--recursive", "--git-submodules", "--format", "ravel-json", "--output", unlistedOutput}); code != 1 {
		t.Fatalf("unlisted gitlink exit=%d", code)
	}
	if _, err := os.Stat(unlistedOutput); !os.IsNotExist(err) {
		t.Fatalf("unlisted gitlink left a partial output: %v", err)
	}
}

func TestSubmoduleURLAndPathBoundaries(t *testing.T) {
	parent, err := validateGitURL("https://github.com/owner/parent.git")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveSubmoduleURL(parent, "../child.git")
	if err != nil || resolved != "https://github.com/owner/child.git" {
		t.Fatalf("relative submodule URL: %q, %v", resolved, err)
	}
	sshParent, err := validateGitURL("ssh://git@github.com/owner/parent.git")
	if err != nil {
		t.Fatal(err)
	}
	sshResolved, err := resolveSubmoduleURL(sshParent, "../child.git")
	if err != nil || sshResolved != "ssh://git@github.com/owner/child.git" {
		t.Fatalf("relative SSH submodule URL: %q, %v", sshResolved, err)
	}
	if _, err := resolveSubmoduleURL(sshParent, "ssh://other@github.com/owner/child.git"); err == nil {
		t.Fatal("submodule with a different SSH username was accepted")
	}
	for _, raw := range []string{"https://elsewhere.invalid/child.git", "ssh://git@github.com/owner/child.git", "file:///tmp/child.git", "https://github.com/owner/child.git?token=x"} {
		if _, err := resolveSubmoduleURL(parent, raw); err == nil {
			t.Fatalf("unsafe submodule URL accepted: %s", raw)
		}
	}
	for _, value := range []string{"../escape", "/absolute", "deps/../escape", ".git/config", "deps\nchild"} {
		if safeSubmodulePath(value) {
			t.Fatalf("unsafe submodule path accepted: %q", value)
		}
	}
	fileRoot := t.TempDir()
	fileParent, err := validateGitURL("file://" + filepath.ToSlash(filepath.Join(fileRoot, "parent.git")))
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(fileRoot, "child.git")); err == nil {
		if _, err := resolveSubmoduleURL(fileParent, "../child.git"); err == nil {
			t.Fatal("file submodule symlink escaping the parent directory was accepted")
		}
	}
}
