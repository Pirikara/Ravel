package gomod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
)

type listedModule struct {
	Path    string        `json:"Path"`
	Version string        `json:"Version"`
	Main    bool          `json:"Main"`
	Replace *listedModule `json:"Replace"`
	Error   *struct {
		Err string `json:"Err"`
	} `json:"Error"`
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		b.exceeded = true
		return 0, errors.New("resolver output limit exceeded")
	}
	return b.buffer.Write(p)
}

func CollectResolved(file, project string, networkAllow bool) (model.Document, error) {
	if filepath.Base(file) != "go.mod" {
		return model.Document{}, errors.New("Go resolver requires go.mod")
	}
	projectDir := filepath.Dir(file)
	if _, err := os.Stat(filepath.Join(projectDir, "go.work")); err == nil {
		return model.Document{}, errors.New("Go workspace resolution is not supported yet")
	}
	modData, err := os.ReadFile(file)
	if err != nil {
		return model.Document{}, err
	}
	manifest, err := modfile.Parse(file, modData, nil)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid go.mod: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "list", "-mod=readonly", "-m", "-json", "all")
	cmd.Dir = projectDir
	env := []string{}
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if key == "GOFLAGS" || key == "GOWORK" || key == "GOTOOLCHAIN" || !networkAllow && (key == "GOPROXY" || key == "GOSUMDB" || key == "GOVCS") {
			continue
		}
		env = append(env, item)
	}
	env = append(env, "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local")
	if !networkAllow {
		env = append(env, "GOPROXY=off", "GOSUMDB=off", "GOVCS=*:off")
	}
	cmd.Env = env
	stdout := &boundedBuffer{limit: 64 << 20}
	stderr := &boundedBuffer{limit: 1 << 20}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err = cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return model.Document{}, errors.New("go list output exceeded size limit")
	}
	if err != nil {
		if ctx.Err() != nil {
			return model.Document{}, fmt.Errorf("go list timed out: %w", ctx.Err())
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return model.Document{}, fmt.Errorf("go list failed (exit code %d)", exit.ExitCode())
		}
		return model.Document{}, fmt.Errorf("go list failed: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.buffer.Bytes()))
	selected := map[string]listedModule{}
	for {
		var item listedModule
		err := decoder.Decode(&item)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return model.Document{}, fmt.Errorf("invalid go list output: %w", err)
		}
		if item.Main {
			continue
		}
		if item.Error != nil {
			return model.Document{}, errors.New("go list reported an unresolved module")
		}
		if module.CheckPath(item.Path) != nil || !semver.IsValid(item.Version) {
			return model.Document{}, fmt.Errorf("go list returned invalid module identity")
		}
		if _, exists := selected[item.Path]; exists {
			return model.Document{}, fmt.Errorf("go list returned duplicate module %s", item.Path)
		}
		selected[item.Path] = item
	}
	var paths []string
	for path := range selected {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	canonical := make([]listedModule, 0, len(paths))
	for _, path := range paths {
		item := selected[path]
		canonical = append(canonical, listedModule{Path: item.Path, Version: item.Version, Replace: item.Replace})
	}
	canonicalData, err := json.Marshal(canonical)
	if err != nil {
		return model.Document{}, err
	}
	doc := common.NewDocument(file, project, "go", modData)
	mainRef, err := addMainModule(&doc, manifest, file, modData)
	if err != nil {
		return model.Document{}, err
	}
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "transitive_graph_unavailable"})
	refs := map[string]string{}
	for _, path := range paths {
		item := selected[path]
		ref := "go:" + common.ID(item.Path+"|"+item.Version+"|"+replacementKey(item.Replace))
		refs[path] = ref
		ev := common.Evidence("go list -m -json all", "go-resolver", "/module/"+common.ID(path), canonicalData)
		ev.Method = "resolver-output"
		identity := ""
		if item.Replace == nil {
			identity = common.GoModulePURL(item.Path, item.Version)
		}
		doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "package", Name: item.Path, Version: item.Version, PURL: identity, Evidence: []model.Evidence{ev}})
		addResolvedOrigin(&doc, ref, item, ev)
	}
	for _, req := range manifest.Require {
		if req.Indirect {
			continue
		}
		ref := refs[req.Mod.Path]
		if ref == "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unresolved_dependency", Name: req.Mod.Path})
			continue
		}
		doc.Edges = append(doc.Edges, model.Edge{From: mainRef, To: ref, Kind: "direct", Evidence: common.Evidence(file, "go-manifest", "/require/"+common.ID(req.Mod.Path), modData)})
	}
	common.Finalize(&doc)
	return doc, nil
}

func replacementKey(item *listedModule) string {
	if item == nil {
		return ""
	}
	return item.Path + "|" + item.Version
}

func addResolvedOrigin(doc *model.Document, ref string, item listedModule, ev model.Evidence) {
	if item.Replace == nil {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "missing_source", Name: item.Path})
		return
	}
	if item.Replace.Version == "" {
		doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "local", Status: "declared", Evidence: ev})
		return
	}
	if module.CheckPath(item.Replace.Path) != nil || !semver.IsValid(item.Replace.Version) {
		doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source", Name: item.Path})
		return
	}
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "module_replacement", Target: item.Replace.Path + "@" + item.Replace.Version, Status: "declared", Evidence: ev})
	doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "source_unresolved", Name: item.Path})
}
