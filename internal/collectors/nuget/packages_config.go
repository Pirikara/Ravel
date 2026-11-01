package nuget

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const maxPackagesConfigBytes = 16 << 20

var configID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
var configVersion = regexp.MustCompile(`^[0-9][A-Za-z0-9.+-]{0,127}$`)
var configTFM = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]{0,127}$`)

// CollectPackagesConfig reads NuGet's legacy flat installed-package list.
// The file contains transitive packages but does not identify which package
// required another or which configured source supplied a distribution.
func CollectPackagesConfig(filename, project string) (model.Document, error) {
	file, err := os.Open(filename)
	if err != nil {
		return model.Document{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return model.Document{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxPackagesConfigBytes {
		return model.Document{}, errors.New("packages.config size is invalid or exceeds 16 MiB")
	}
	data := make([]byte, info.Size())
	if _, err := io.ReadFull(file, data); err != nil {
		return model.Document{}, err
	}
	input := bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	decoder := xml.NewDecoder(bytes.NewReader(input))
	decoder.Strict = true
	doc := common.NewDocument(filename, project, "nuget", data)
	baseEvidence := common.Evidence(filename, "nuget-packages-config", "", data)
	opened, closed := false, false
	seen := map[string]bool{}
	index := 0
	for {
		tok, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid packages.config XML: %w", err)
		}
		switch item := tok.(type) {
		case xml.StartElement:
			if !opened && !closed && item.Name.Space == "" && item.Name.Local == "packages" {
				opened = true
				continue
			}
			if !opened || closed || item.Name.Space != "" || item.Name.Local != "package" {
				return model.Document{}, errors.New("packages.config has an unexpected XML element")
			}
			attrs := map[string]string{}
			for _, attr := range item.Attr {
				_, duplicate := attrs[attr.Name.Local]
				if attr.Name.Space != "" || duplicate {
					return model.Document{}, errors.New("packages.config has a namespaced or duplicate attribute")
				}
				attrs[attr.Name.Local] = attr.Value
			}
			name, version := attrs["id"], attrs["version"]
			if !configID.MatchString(name) || !configVersion.MatchString(version) {
				return model.Document{}, fmt.Errorf("packages.config entry %d has invalid package identity", index)
			}
			if attrs["developmentDependency"] != "" && attrs["developmentDependency"] != "true" && attrs["developmentDependency"] != "false" {
				return model.Document{}, fmt.Errorf("packages.config entry %d has invalid developmentDependency", index)
			}
			var body struct {
				Inner string `xml:",innerxml"`
			}
			if err := decoder.DecodeElement(&body, &item); err != nil || strings.TrimSpace(body.Inner) != "" {
				return model.Document{}, fmt.Errorf("packages.config entry %d must be empty", index)
			}
			key := strings.ToLower(name)
			if seen[key] {
				return model.Document{}, fmt.Errorf("packages.config contains duplicate package %q", name)
			}
			seen[key] = true
			evidence := baseEvidence
			evidence.Pointer = fmt.Sprintf("/packages/%d", index)
			id := "nuget-config:" + common.ID(filename+"\x00"+key+"\x00"+version)
			context := ""
			if tfm := attrs["targetFramework"]; tfm != "" {
				if !configTFM.MatchString(tfm) {
					return model.Document{}, fmt.Errorf("packages.config entry %d has invalid targetFramework", index)
				}
				context = "installed-target-framework=" + tfm
			}
			if attrs["developmentDependency"] == "true" {
				if context != "" {
					context += ";"
				}
				context += "developmentDependency=true"
			}
			doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: version, Context: context, Evidence: []model.Evidence{evidence}})
			doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "listed", Evidence: evidence})
			index++
			if index > 100000 {
				return model.Document{}, errors.New("packages.config has too many entries")
			}
		case xml.EndElement:
			if !opened || closed || item.Name.Space != "" || item.Name.Local != "packages" {
				return model.Document{}, errors.New("packages.config has an unexpected closing element")
			}
			closed = true
		case xml.CharData:
			if strings.TrimSpace(string(item)) != "" {
				return model.Document{}, errors.New("packages.config contains unexpected text")
			}
		case xml.Directive:
			return model.Document{}, errors.New("packages.config cannot contain XML directives")
		}
	}
	if !opened || !closed {
		return model.Document{}, errors.New("packages.config must have a packages root element")
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues,
		model.Issue{Code: "nuget_packages_config_graph_unavailable"},
		model.Issue{Code: "nuget_packages_config_origin_unverified"},
		model.Issue{Code: "nuget_packages_config_installation_unverified"})
	common.Finalize(&doc)
	return doc, nil
}
