package main

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxGitLFSPointerBytes = 1023
const maxReportedGitLFSPointers = 32

var gitLFSOID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// gitLFSPointerPaths checks the bounded checkout, including fetched submodules.
// Git LFS smudge is disabled during remote checkout, so a pointer is evidence
// that the corresponding file contents were not available to the scanner.
func gitLFSPointerPaths(checkout string) ([]string, bool, error) {
	paths := []string{}
	limited := false
	err := filepath.WalkDir(checkout, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() < 100 || info.Size() > maxGitLFSPointerBytes {
			return nil
		}
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, maxGitLFSPointerBytes+1))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if !isGitLFSPointer(data) {
			return nil
		}
		if len(paths) == maxReportedGitLFSPointers {
			limited = true
			return filepath.SkipAll
		}
		relative, err := filepath.Rel(checkout, name)
		if err != nil {
			return err
		}
		paths = append(paths, filepath.ToSlash(relative))
		return nil
	})
	return paths, limited, err
}

func isGitLFSPointer(data []byte) bool {
	if len(data) >= 1024 || !utf8.Valid(data) {
		return false
	}
	content := string(data)
	if !strings.HasSuffix(content, "\n") || strings.ContainsRune(content, '\r') {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if len(lines) < 3 || lines[0] != "version https://git-lfs.github.com/spec/v1" {
		return false
	}
	previous := ""
	hasOID, hasSize := false, false
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(line, " ")
		if !ok || key <= previous || value == "" {
			return false
		}
		previous = key
		switch key {
		case "oid":
			hasOID = gitLFSOID.MatchString(value)
			if !hasOID {
				return false
			}
		case "size":
			if strings.Trim(value, "0123456789") != "" {
				return false
			}
			_, err := strconv.ParseUint(value, 10, 64)
			hasSize = err == nil
			if !hasSize {
				return false
			}
		default:
			if !strings.HasPrefix(key, "ext-") || strings.ContainsRune(value, ' ') {
				return false
			}
		}
	}
	return hasOID && hasSize
}
