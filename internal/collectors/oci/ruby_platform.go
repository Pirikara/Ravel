package oci

import (
	"errors"
	"path"
	"regexp"
	"strings"

	"github.com/Pirikara/Ravel/internal/model"
)

const (
	maxRubyPlatformConfigBytes = 256 << 10
	maxRubyPlatformConfigs     = 16
)

var rubyPlatformConfigPath = regexp.MustCompile(`^usr/local/lib/ruby/([0-9]{1,2}\.[0-9]{1,2}\.0)/((?:x86_64|aarch64)-linux(?:-(?:gnu|musl))?)/rbconfig\.rb$`)

type rubyPlatformConfigState struct {
	platform string
	status   string
	evidence model.Evidence
}

func isRubyPlatformConfigPath(name string) bool {
	return rubyPlatformConfigPath.MatchString(name)
}

// RubyGems reads the generated RbConfig arch field for its local platform.
// Accept only literal values that agree with the final file path and image CPU.
func inspectRubyPlatformConfig(data []byte, name, architecture string) (string, int, error) {
	parts := rubyPlatformConfigPath.FindStringSubmatch(name)
	if len(data) == 0 || len(data) > maxRubyPlatformConfigBytes || parts == nil {
		return "", 0, errors.New("invalid Ruby platform config path or size")
	}
	cpu := ""
	switch architecture {
	case "amd64":
		cpu = "x86_64"
	case "arm64":
		cpu = "aarch64"
	}
	if cpu == "" || !strings.HasPrefix(parts[2], cpu+"-linux") {
		return "", 0, errors.New("Ruby platform config contradicts image architecture")
	}
	archLine := `CONFIG["arch"] = "` + parts[2] + `"`
	versionLine := `CONFIG["ruby_version"] = "` + parts[1] + `"`
	archCount, versionCount := 0, 0
	archLineNumber := 0
	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `CONFIG["arch"]`) {
			archCount++
			if line != archLine {
				return "", 0, errors.New("Ruby platform arch is not a matching literal")
			}
			archLineNumber = index + 1
		}
		if strings.HasPrefix(line, `CONFIG["ruby_version"]`) {
			versionCount++
			if line != versionLine {
				return "", 0, errors.New("Ruby platform ABI is not a matching literal")
			}
		}
	}
	if archCount != 1 || versionCount != 1 {
		return "", 0, errors.New("Ruby platform config is ambiguous or incomplete")
	}
	return parts[2], archLineNumber, nil
}

func rubyLocalPlatform(runtimes map[string]rubyRuntimeState, configs map[string]rubyPlatformConfigState) rubyPlatformConfigState {
	home := rubyDefaultGemHome(runtimes)
	if home == "" || len(configs) != 1 {
		return rubyPlatformConfigState{}
	}
	abi := path.Base(home)
	for name, state := range configs {
		if state.status == "" && strings.HasPrefix(name, "usr/local/lib/ruby/"+abi+"/") {
			return state
		}
	}
	return rubyPlatformConfigState{}
}

// This intentionally supports only the Linux CPU and libc forms validated by
// the local rbconfig. Other gem platform forms remain unverified.
func rubyLinuxGemPlatformMatches(gemPlatform, localPlatform string) (match, known bool) {
	gemCPU, gemLibc, gemOK := rubyLinuxPlatform(gemPlatform)
	localCPU, localLibc, localOK := rubyLinuxPlatform(localPlatform)
	if !gemOK || !localOK {
		return false, false
	}
	return gemCPU == localCPU && gemLibc == localLibc, true
}

func rubyLinuxPlatform(value string) (cpu, libc string, ok bool) {
	for _, candidate := range []string{"x86_64", "aarch64"} {
		if value == candidate+"-linux" || value == candidate+"-linux-gnu" {
			return candidate, "gnu", true
		}
		if value == candidate+"-linux-musl" {
			return candidate, "musl", true
		}
	}
	return "", "", false
}
