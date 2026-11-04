package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Pirikara/Ravel/internal/model"
)

type spdxExternalRef struct {
	Category string `json:"referenceCategory"`
	Type     string `json:"referenceType"`
	Locator  string `json:"referenceLocator"`
}

type spdxChecksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

type spdxPackage struct {
	ID               string            `json:"SPDXID"`
	Name             string            `json:"name"`
	Version          string            `json:"versionInfo,omitempty"`
	Purpose          string            `json:"primaryPackagePurpose"`
	Comment          string            `json:"comment,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
}

type spdxRelationship struct {
	From string `json:"spdxElementId"`
	Type string `json:"relationshipType"`
	To   string `json:"relatedSpdxElement"`
}

type spdxDocument struct {
	Version           string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	ID                string             `json:"SPDXID"`
	Name              string             `json:"name"`
	Namespace         string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships,omitempty"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDX23 exports selected package occurrences and unconditional dependency edges.
// Ravel JSON remains the source for evidence, conditional edges, and coverage.
func SPDX23(doc model.Document) ([]byte, error) {
	created := time.Now().UTC()
	if raw := os.Getenv("SOURCE_DATE_EPOCH"); raw != "" {
		seconds, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || seconds < 0 {
			return nil, fmt.Errorf("invalid SOURCE_DATE_EPOCH: %q", raw)
		}
		created = time.Unix(seconds, 0).UTC()
	}
	canonical, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	createdText := created.Format("2006-01-02T15:04:05Z")
	contentHash := sha256.Sum256(append(canonical, []byte("\x00"+createdText)...))
	out := spdxDocument{
		Version: "SPDX-2.3", DataLicense: "CC0-1.0", ID: "SPDXRef-DOCUMENT",
		Name: doc.Project, Namespace: "https://spdx.org/spdxdocs/ravel-" + hex.EncodeToString(contentHash[:]),
		CreationInfo:      spdxCreationInfo{Created: createdText, Creators: []string{"Tool: Ravel"}},
		DocumentDescribes: []string{"SPDXRef-Root"}, Packages: []spdxPackage{},
	}
	root := spdxPackage{ID: "SPDXRef-Root", Name: doc.Project, Purpose: "APPLICATION", DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"}
	for _, runtime := range doc.Runtimes {
		if root.Comment != "" {
			root.Comment += "; "
		}
		root.Comment += "Repository runtime declaration (not installed): " + runtime.Name + " " + runtime.Relation + " " + runtime.Requirement
		if runtime.Policy != "" {
			root.Comment += " (policy " + runtime.Policy + ")"
		}
	}
	out.Packages = append(out.Packages, root)
	ids := map[string]string{"root": root.ID}
	for _, c := range doc.Components {
		if c.ID == "" || c.ID == "root" {
			return nil, fmt.Errorf("invalid component ID %q", c.ID)
		}
		if _, exists := ids[c.ID]; exists {
			return nil, fmt.Errorf("duplicate component ID %q", c.ID)
		}
		idHash := sha256.Sum256([]byte(c.ID))
		id := "SPDXRef-Package-" + hex.EncodeToString(idHash[:])
		ids[c.ID] = id
		purpose := "LIBRARY"
		if c.Kind == "module" || c.Kind == "file" {
			purpose = "FILE"
		} else if c.Kind == "application" {
			purpose = "APPLICATION"
		}
		item := spdxPackage{ID: id, Name: c.Name, Version: c.Version, Purpose: purpose, DownloadLocation: "NOASSERTION", LicenseConcluded: "NOASSERTION", LicenseDeclared: "NOASSERTION", CopyrightText: "NOASSERTION"}
		if c.Context != "" {
			item.Comment = "Ravel context: " + c.Context
		}
		if len(c.Patches) > 0 {
			for _, hash := range c.Hashes {
				if item.Comment != "" {
					item.Comment += "; "
				}
				item.Comment += "Ravel base artifact hash: " + hash.Alg + ":" + hash.Content
			}
			for _, patch := range c.Patches {
				if item.Comment != "" {
					item.Comment += "; "
				}
				item.Comment += "Ravel patch: " + strconv.Quote(patch.Path) + " status=" + patch.Status
				if patch.Hash != nil {
					item.Comment += " hash=" + patch.Hash.Alg + ":" + patch.Hash.Content
				}
			}
		}
		for _, source := range doc.Development {
			if source.Occurrence != c.ID {
				continue
			}
			if item.Comment != "" {
				item.Comment += "; "
			}
			item.Comment += "Declared development repository: " + source.SafeURL
		}
		if c.PURL != "" {
			item.ExternalRefs = []spdxExternalRef{{Category: "PACKAGE-MANAGER", Type: "purl", Locator: c.PURL}}
		}
		for _, h := range c.Hashes {
			if len(c.Patches) > 0 {
				continue
			}
			algorithm := strings.ReplaceAll(strings.ToUpper(h.Alg), "-", "")
			if algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA384" && algorithm != "SHA512" && algorithm != "MD5" {
				continue
			}
			item.Checksums = append(item.Checksums, spdxChecksum{Algorithm: algorithm, Value: strings.ToLower(h.Content)})
		}
		out.Packages = append(out.Packages, item)
	}
	seen := map[spdxRelationship]bool{}
	for _, e := range doc.Edges {
		if e.Condition != "" {
			continue
		}
		from, okFrom := ids[e.From]
		to, okTo := ids[e.To]
		if !okFrom || !okTo {
			return nil, fmt.Errorf("dependency references unknown component: %q -> %q", e.From, e.To)
		}
		rel := spdxRelationship{From: from, Type: "DEPENDS_ON", To: to}
		if !seen[rel] {
			out.Relationships = append(out.Relationships, rel)
			seen[rel] = true
		}
	}
	sort.Slice(out.Relationships, func(i, j int) bool {
		a, b := out.Relationships[i], out.Relationships[j]
		if a.From != b.From {
			return a.From < b.From
		}
		return a.To < b.To
	})
	return json.MarshalIndent(out, "", "  ")
}
