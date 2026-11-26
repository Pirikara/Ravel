package python

import (
	"strconv"
	"strings"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

func metadataDevelopment(doc *model.Document, occurrence string, headers []wheelHeader, evidence model.Evidence) {
	explicit := false
	for i, h := range headers {
		if h.name != "project-url" {
			continue
		}
		label, value, ok := strings.Cut(h.value, ",")
		if !ok || !wheelSourceLabel(label) {
			continue
		}
		e := evidence
		e.Pointer += "/project-url/" + strconv.Itoa(i)
		before := len(doc.Development)
		common.AddDevelopment(doc, occurrence, strings.TrimSpace(value), "declared", e)
		explicit = explicit || len(doc.Development) > before
	}
	if explicit {
		return
	}
	for i, h := range headers {
		value, field := h.value, h.name
		if h.name == "project-url" {
			label, url, ok := strings.Cut(h.value, ",")
			if !ok || normalizedProjectLabel(label) != "homepage" {
				continue
			}
			value = strings.TrimSpace(url)
		} else if h.name != "home-page" {
			continue
		}
		if value := common.RepositoryHomepage(value); value != "" {
			e := evidence
			e.Pointer += "/" + field + "/" + strconv.Itoa(i)
			common.AddDevelopment(doc, occurrence, value, "inferred_from_homepage", e)
		}
	}
}
