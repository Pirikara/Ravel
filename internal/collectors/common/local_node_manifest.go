package common

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ReadLocalNodeManifest reads bounded static metadata within the lock's root.
func ReadLocalNodeManifest(lockfile, directory string) ([]byte, string, error) {
	if !filepath.IsLocal(directory) || strings.ContainsAny(directory, "\\\x00\r\n") {
		return nil, "", fmt.Errorf("invalid local package directory")
	}
	root, err := os.OpenRoot(filepath.Dir(lockfile))
	if err != nil {
		return nil, "", err
	}
	defer root.Close()
	name := filepath.Join(directory, "package.json")
	file, err := root.Open(name)
	if err != nil {
		return nil, "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, "", fmt.Errorf("local manifest is not a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > 1<<20 {
		return nil, "", fmt.Errorf("local manifest exceeds size limit")
	}
	return data, filepath.Join(filepath.Dir(lockfile), name), nil
}
