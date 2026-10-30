package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path"
	"regexp"
	"strings"

	"ravel/internal/collectors/common"
	"ravel/internal/model"
)

const (
	maxRubySpecBytes = 1 << 20
	maxRubySpecFiles = 5000
	maxRubySpecTotal = 64 << 20
)

var rubySpecPath = regexp.MustCompile(`^(?:(?:usr/local/lib|usr/lib|var/lib)/ruby/gems/[0-9]+\.[0-9]+\.[0-9]+|usr/local/bundle)/specifications/(?:default/)?[^/]+\.gemspec$`)
var rubyStub = regexp.MustCompile(`(?m)^# stub: ([A-Za-z0-9][A-Za-z0-9_.-]{0,127}) ([0-9][A-Za-z0-9_.-]{0,127}) ([A-Za-z0-9_.-]+)(?: [^\r\n]*)?\r?$`)
var rubySpecConstructor = regexp.MustCompile(`(?m)^Gem::Specification\.new do \|s\|\r?$`)
var rubyNameAssignment = regexp.MustCompile(`(?m)^[ \t]*s\.name[ \t]*=`)
var rubyVersionAssignment = regexp.MustCompile(`(?m)^[ \t]*s\.version[ \t]*=`)
var rubyNameLiteral = regexp.MustCompile(`(?m)^[ \t]*s\.name[ \t]*=[ \t]*"([A-Za-z0-9][A-Za-z0-9_.-]{0,127})"(?:\.freeze)?[ \t]*\r?$`)
var rubyVersionLiteral = regexp.MustCompile(`(?m)^[ \t]*s\.version[ \t]*=[ \t]*"([0-9][A-Za-z0-9_.-]{0,127})"(?:\.freeze)?[ \t]*\r?$`)

func isInstalledRubySpecPath(name string) bool {
	return rubySpecPath.MatchString(name)
}

// inspectInstalledRubySpec uses only the generated stub and literal identity
// fields. It never evaluates the Ruby code in an installed gemspec.
func inspectInstalledRubySpec(data []byte, source, project, filename string) (model.Document, error) {
	if len(data) == 0 || len(data) > maxRubySpecBytes || !isInstalledRubySpecPath(filename) {
		return model.Document{}, errors.New("invalid installed Ruby gemspec path or size")
	}
	stubs := rubyStub.FindAllSubmatch(data, -1)
	names := rubyNameLiteral.FindAllSubmatch(data, -1)
	versions := rubyVersionLiteral.FindAllSubmatch(data, -1)
	if len(stubs) != 1 || len(names) != 1 || len(versions) != 1 || len(rubySpecConstructor.FindAll(data, -1)) != 1 || len(rubyNameAssignment.FindAll(data, -1)) != 1 || len(rubyVersionAssignment.FindAll(data, -1)) != 1 {
		return model.Document{}, errors.New("installed Ruby gemspec identity is ambiguous or unavailable")
	}
	name, version, platform := string(stubs[0][1]), string(stubs[0][2]), string(stubs[0][3])
	if string(names[0][1]) != name || string(versions[0][1]) != version {
		return model.Document{}, errors.New("installed Ruby gemspec identity contradicts stub")
	}
	wantFilename := name + "-" + version
	if platform != "ruby" {
		wantFilename += "-" + platform
	}
	if path.Base(filename) != wantFilename+".gemspec" {
		return model.Document{}, errors.New("installed Ruby gemspec filename contradicts identity")
	}
	hash := sha256.Sum256(data)
	digest := hex.EncodeToString(hash[:])
	evidence := model.Evidence{Collector: "ruby-installed-gemspec", InputPath: source, InputDigest: "sha256:" + digest, Pointer: "Gem::Specification/name,version", Method: "installed-gemspec-analysis"}
	doc := common.NewDocument(source, project, "ruby-installed", nil)
	id := "ruby-installed:" + common.ID(source+"\x00"+name+"\x00"+version+"\x00"+platform)
	context := "location=/" + filename
	if strings.Contains(filename, "/specifications/default/") {
		context += ";default=true"
	}
	if platform != "ruby" {
		context += ";gem_platform=" + platform
	}
	doc.Components = append(doc.Components, model.Component{ID: id, Kind: "package", Name: name, Version: version, Context: context, Evidence: []model.Evidence{evidence}})
	doc.Edges = append(doc.Edges, model.Edge{From: "root", To: id, Kind: "installed", Evidence: evidence})
	common.Finalize(&doc)
	return doc, nil
}
