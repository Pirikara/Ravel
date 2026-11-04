// Package vex correlates externally authored OpenVEX statements with Ravel
// components. It does not determine whether a vulnerability is present.
package vex

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/Pirikara/Ravel/internal/model"
)

type document struct {
	Context    string      `json:"@context"`
	ID         string      `json:"@id"`
	Author     string      `json:"author"`
	Timestamp  string      `json:"timestamp"`
	Version    int         `json:"version"`
	Statements []statement `json:"statements"`
}

type statement struct {
	ID              string    `json:"@id"`
	Timestamp       string    `json:"timestamp"`
	Vulnerability   vuln      `json:"vulnerability"`
	Products        []product `json:"products"`
	Status          string    `json:"status"`
	Justification   string    `json:"justification"`
	ImpactStatement string    `json:"impact_statement"`
	ActionStatement string    `json:"action_statement"`
}

type vuln struct {
	Name string `json:"name"`
}

type product struct {
	ID            string            `json:"@id"`
	Identifiers   map[string]string `json:"identifiers"`
	Hashes        map[string]string `json:"hashes"`
	Subcomponents []product         `json:"subcomponents"`
}

type Result struct {
	DocumentID  string            `json:"documentId"`
	InputDigest string            `json:"inputDigest"`
	Author      string            `json:"author"`
	Timestamp   string            `json:"timestamp"`
	Version     int               `json:"version"`
	Statements  []StatementResult `json:"statements"`
}

type StatementResult struct {
	Index           int             `json:"index"`
	ID              string          `json:"id,omitempty"`
	Timestamp       string          `json:"timestamp"`
	Vulnerability   string          `json:"vulnerability"`
	Status          string          `json:"status"`
	Justification   string          `json:"justification,omitempty"`
	ImpactStatement string          `json:"impactStatement,omitempty"`
	ActionStatement string          `json:"actionStatement,omitempty"`
	Products        []ProductResult `json:"products"`
}

type ProductResult struct {
	ID                string   `json:"id,omitempty"`
	PURL              string   `json:"purl,omitempty"`
	Matched           bool     `json:"matched"`
	MatchMethod       string   `json:"matchMethod,omitempty"`
	ComponentIDs      []string `json:"componentIds,omitempty"`
	Reason            string   `json:"reason,omitempty"`
	SubcomponentPURLs []string `json:"subcomponentPurls,omitempty"`
}

// Correlate uses exact product PURL equality. Subcomponents are shown for
// context but are not used to extend a statement to other SBOM components.
func Correlate(sbom model.Document, data []byte) (Result, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Result{}, fmt.Errorf("invalid OpenVEX JSON: %w", err)
	}
	if doc.Context != "https://openvex.dev/ns/v0.2.0" {
		return Result{}, errors.New("unsupported OpenVEX context (expected v0.2.0)")
	}
	if strings.TrimSpace(doc.ID) == "" || strings.TrimSpace(doc.Author) == "" || doc.Version < 1 || len(doc.Statements) == 0 {
		return Result{}, errors.New("OpenVEX document requires @id, author, positive version, and statements")
	}
	if err := validTime(doc.Timestamp); err != nil {
		return Result{}, fmt.Errorf("OpenVEX document timestamp: %w", err)
	}
	components := make(map[string][]string)
	for _, component := range sbom.Components {
		if component.PURL != "" {
			components[component.PURL] = append(components[component.PURL], component.ID)
		}
	}
	for _, ids := range components {
		sort.Strings(ids)
	}
	result := Result{DocumentID: doc.ID, InputDigest: fmt.Sprintf("sha256:%x", sha256.Sum256(data)), Author: doc.Author, Timestamp: doc.Timestamp, Version: doc.Version, Statements: make([]StatementResult, 0, len(doc.Statements))}
	for i, s := range doc.Statements {
		if strings.TrimSpace(s.Vulnerability.Name) == "" || len(s.Products) == 0 {
			return Result{}, fmt.Errorf("OpenVEX statement %d requires vulnerability name and products", i+1)
		}
		switch s.Status {
		case "not_affected":
			if s.Justification == "" && strings.TrimSpace(s.ImpactStatement) == "" {
				return Result{}, fmt.Errorf("OpenVEX statement %d: not_affected requires justification or impact_statement", i+1)
			}
			if s.Justification != "" && !validJustification(s.Justification) {
				return Result{}, fmt.Errorf("OpenVEX statement %d: unsupported justification %q", i+1, s.Justification)
			}
		case "affected":
			if strings.TrimSpace(s.ActionStatement) == "" {
				return Result{}, fmt.Errorf("OpenVEX statement %d: affected requires action_statement", i+1)
			}
		case "fixed", "under_investigation":
		default:
			return Result{}, fmt.Errorf("OpenVEX statement %d: unsupported status %q", i+1, s.Status)
		}
		timestamp := doc.Timestamp
		if s.Timestamp != "" {
			if err := validTime(s.Timestamp); err != nil {
				return Result{}, fmt.Errorf("OpenVEX statement %d timestamp: %w", i+1, err)
			}
			timestamp = s.Timestamp
		}
		entry := StatementResult{Index: i + 1, ID: s.ID, Timestamp: timestamp, Vulnerability: s.Vulnerability.Name, Status: s.Status, Justification: s.Justification, ImpactStatement: s.ImpactStatement, ActionStatement: s.ActionStatement, Products: make([]ProductResult, 0, len(s.Products))}
		for j, p := range s.Products {
			purl, err := productPURL(p)
			if err != nil {
				return Result{}, fmt.Errorf("OpenVEX statement %d product %d: %w", i+1, j+1, err)
			}
			item := ProductResult{ID: p.ID, PURL: purl, Matched: len(components[purl]) > 0 && purl != "", ComponentIDs: components[purl]}
			if item.Matched {
				item.MatchMethod = "exact_purl"
			}
			for k, sub := range p.Subcomponents {
				subPURL, err := productPURL(sub)
				if err != nil {
					return Result{}, fmt.Errorf("OpenVEX statement %d product %d subcomponent %d: %w", i+1, j+1, k+1, err)
				}
				if subPURL != "" {
					item.SubcomponentPURLs = append(item.SubcomponentPURLs, subPURL)
				}
			}
			if !item.Matched {
				if purl == "" {
					item.Reason = "no_purl"
				} else {
					item.Reason = "purl_not_in_sbom"
				}
			}
			entry.Products = append(entry.Products, item)
		}
		result.Statements = append(result.Statements, entry)
	}
	return result, nil
}

func productPURL(p product) (string, error) {
	fromID := ""
	if strings.HasPrefix(p.ID, "pkg:") {
		fromID = p.ID
	}
	fromIdentifiers := p.Identifiers["purl"]
	if fromID != "" && fromIdentifiers != "" && fromID != fromIdentifiers {
		return "", errors.New("conflicting @id and identifiers.purl")
	}
	purl := fromIdentifiers
	if purl == "" {
		purl = fromID
	}
	if purl == "" {
		if strings.TrimSpace(p.ID) == "" && len(p.Identifiers) == 0 && len(p.Hashes) == 0 {
			return "", errors.New("product has no identifier")
		}
		return "", nil
	}
	if _, err := packageurl.FromString(purl); err != nil {
		return "", fmt.Errorf("invalid purl %q: %w", purl, err)
	}
	return purl, nil
}

func validJustification(value string) bool {
	switch value {
	case "component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist":
		return true
	default:
		return false
	}
}

func validTime(value string) error {
	if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
		return fmt.Errorf("expected RFC 3339 timestamp: %w", err)
	}
	return nil
}
