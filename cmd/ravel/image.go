package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/oci"
	"github.com/Pirikara/Ravel/internal/model"
)

func looksLikeImageReference(value string) bool {
	if strings.Contains(value, "://") || strings.HasPrefix(value, "git@") || strings.ContainsAny(value, " \t\n") {
		return false
	}
	last := value[strings.LastIndex(value, "/")+1:]
	return strings.Contains(last, ":") || strings.Contains(last, "@sha256:") || strings.Contains(value, "@sha256:")
}

func runScanImage(reference, platform, format, output, reportPath string, strict, docker bool) int {
	if reportPath == "-" || reportPath != "" && samePath(reportPath, output) {
		fmt.Fprintln(os.Stderr, "ravel: output and report must be distinct files")
		return 2
	}
	if format != "cyclonedx-json" && format != "spdx-json" && format != "ravel-json" {
		fmt.Fprintln(os.Stderr, "ravel: unsupported format")
		return 2
	}
	var doc model.Document
	var err error
	if docker {
		doc, err = oci.CollectDockerReference(reference, platform)
	} else {
		doc, err = oci.CollectReference(reference, platform)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	return writeScanResult(doc, format, output, reportPath, strict)
}
