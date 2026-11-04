package main

import (
	"fmt"

	"github.com/Pirikara/Ravel/internal/collectors/runtimeversion"
	"github.com/Pirikara/Ravel/internal/model"
)

func repositoryManager(manager string) bool {
	switch manager {
	case "oci", "java-archive", "ruby-gem", "python-wheel", "npm-archive", "nuget-archive", "dpkg", "apk", "rpm":
		return false
	}
	return true
}

func attachRuntimeRequirements(doc *model.Document, declarations runtimeversion.Result, output, reportPath string) error {
	seen := map[string]bool{doc.Source: true}
	for _, source := range doc.Sources {
		seen[source] = true
	}
	for _, source := range declarations.Sources {
		if samePath(output, source) || reportPath != "" && samePath(reportPath, source) {
			return fmt.Errorf("output and report cannot overwrite a discovered input: %s", source)
		}
		if !seen[source] {
			seen[source] = true
			doc.Sources = append(doc.Sources, source)
		}
	}
	doc.Runtimes = append(doc.Runtimes, declarations.Requirements...)
	doc.Coverage.Issues = append(doc.Coverage.Issues, declarations.Issues...)
	return nil
}
