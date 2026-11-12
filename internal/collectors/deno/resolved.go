package deno

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/evanw/esbuild/pkg/api"
	"github.com/tailscale/hujson"

	"github.com/Pirikara/Ravel/internal/collectors/common"
	"github.com/Pirikara/Ravel/internal/model"
	"github.com/Pirikara/Ravel/internal/safeurl"
)

const (
	maxRemoteModules = 512
	maxRemoteBytes   = 64 << 20
	maxRemoteFile    = 2 << 20
)

type remoteFetcher func(context.Context, string) ([]byte, string, error)

// CollectResolved follows remote imports only when explicitly allowed to use
// the network. Each fetched module must match the digest in deno.lock before
// its imports can establish dependency edges. Unreached lock entries remain
// unknown: Deno can retain records for modules no longer used by the project.
func CollectResolved(file, project string, networkAllow bool) (model.Document, error) {
	if !networkAllow {
		return Collect(file, project)
	}
	fetch, closeConnections := newRemoteFetcher()
	defer closeConnections()
	return collectResolved(file, project, fetch)
}

func collectResolved(file, project string, fetch remoteFetcher) (model.Document, error) {
	doc, err := Collect(file, project)
	if err != nil {
		return doc, err
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return doc, err
	}
	var lock lockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return doc, err
	}
	imports, scopes := resolvedImportMap(filepath.Dir(file))
	urls := make(map[string]string, len(lock.Remote))
	queue := make([]string, 0)
	for raw := range lock.Remote {
		ref := remoteRef(raw)
		urls[ref] = raw
	}
	for _, component := range doc.Components {
		if raw, ok := urls[component.ID]; ok {
			queue = append(queue, raw)
		}
	}
	sort.Strings(queue)
	seen := map[string]bool{}
	edges := map[string]bool{}
	for _, edge := range doc.Edges {
		edges[edge.From+"\x00"+edge.To] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	totalBytes := 0
	for len(queue) > 0 {
		raw := queue[0]
		queue = queue[1:]
		if seen[raw] {
			continue
		}
		seen[raw] = true
		clean := safeurl.Clean(raw)
		if len(seen) > maxRemoteModules || totalBytes >= maxRemoteBytes || ctx.Err() != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "remote_source_scan_limited", Name: clean})
			break
		}
		if !validRemoteURL(raw) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "remote_source_unavailable", Name: clean})
			continue
		}
		body, finalURL, err := fetch(ctx, raw)
		if err != nil || len(body) > maxRemoteFile || totalBytes+len(body) > maxRemoteBytes {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "remote_source_unavailable", Name: clean})
			continue
		}
		totalBytes += len(body)
		want, err := hex.DecodeString(lock.Remote[raw])
		sum := sha256.Sum256(body)
		if err != nil || len(want) != sha256.Size || !equalDigest(want, sum[:]) {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "remote_source_integrity_mismatch", Name: clean})
			continue
		}
		specs, err := remoteImports(finalURL, body)
		if err != nil {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "remote_source_parse_error", Name: clean})
			continue
		}
		ev := common.Evidence(clean, "deno-remote-source", "", body)
		ev.Method = "integrity-verified-source"
		for i := range doc.Components {
			if doc.Components[i].ID == remoteRef(raw) {
				doc.Components[i].Evidence = append(doc.Components[i].Evidence, ev)
				break
			}
		}
		ev.Method = "verified-remote-import"
		for _, spec := range specs {
			mapped := mappedRemoteSpecifier(spec, raw, imports, scopes)
			if mapped != "" {
				// Import-map relative values are relative to the map file,
				// not to the importing remote module.
				if strings.HasPrefix(mapped, "./") || strings.HasPrefix(mapped, "../") || strings.HasPrefix(mapped, "/") {
					doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "remote_import_unresolved", Name: clean})
					continue
				}
				spec = mapped
			}
			child := resolveRemoteSpecifier(finalURL, spec)
			if child == "" {
				if strings.HasPrefix(spec, "node:") || strings.HasPrefix(spec, "data:") {
					continue
				}
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "remote_import_unresolved", Name: clean})
				continue
			}
			if _, ok := lock.Remote[child]; !ok {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "remote_import_absent_from_lock", Name: safeurl.Clean(child)})
				continue
			}
			if !validRemoteURL(child) || safeurl.Clean(child) == "" {
				doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "unsafe_or_invalid_source"})
				continue
			}
			ref := remoteRef(child)
			if !edges[remoteRef(raw)+"\x00"+ref] {
				edges[remoteRef(raw)+"\x00"+ref] = true
				doc.Edges = append(doc.Edges, model.Edge{From: remoteRef(raw), To: ref, Kind: "depends_on", Evidence: ev})
			}
			if !hasComponent(doc.Components, ref) {
				addRemoteComponent(&doc, file, data, child, lock.Remote[child])
			}
			if !seen[child] {
				queue = append(queue, child)
			}
		}
	}
	// A URL only enters the document through a project import or an import
	// parsed from integrity-verified remote source. Remove the corresponding
	// unknown-reachability issue, including for modules whose own fetch failed.
	reached := map[string]bool{}
	for _, component := range doc.Components {
		if raw, ok := urls[component.ID]; ok {
			reached[raw] = true
		}
	}
	issues := doc.Coverage.Issues[:0]
	for _, issue := range doc.Coverage.Issues {
		if issue.Code != "lock_remote_reachability_unknown" {
			issues = append(issues, issue)
		}
	}
	doc.Coverage.Issues = issues
	for raw := range lock.Remote {
		if !reached[raw] && safeurl.Clean(raw) != "" {
			doc.Coverage.Issues = append(doc.Coverage.Issues, model.Issue{Code: "lock_remote_reachability_unknown", Name: safeurl.Clean(raw)})
		}
	}
	common.Finalize(&doc)
	return doc, nil
}

func remoteRef(raw string) string { return "deno:remote:" + common.ID("remote:"+raw) }

func hasComponent(components []model.Component, ref string) bool {
	for _, component := range components {
		if component.ID == ref {
			return true
		}
	}
	return false
}

func addRemoteComponent(doc *model.Document, file string, lockData []byte, raw, digest string) {
	ref := remoteRef(raw)
	clean := safeurl.Clean(raw)
	ev := common.Evidence(file, "deno-lock", "/remote", lockData)
	doc.Components = append(doc.Components, model.Component{ID: ref, Kind: "module", Name: clean, Hashes: common.HexSHA256(digest), Evidence: []model.Evidence{ev}})
	doc.Origins = append(doc.Origins, model.Origin{Occurrence: ref, Kind: "download_url", SafeURL: clean, Status: "declared", Evidence: ev})
}

func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func resolvedImportMap(base string) (map[string]string, map[string]map[string]string) {
	for _, name := range []string{"deno.json", "deno.jsonc"} {
		data, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			continue
		}
		data, err = hujson.Standardize(data)
		if err != nil {
			break
		}
		var config configFile
		if json.Unmarshal(data, &config) != nil {
			break
		}
		if config.ImportMap != "" {
			if imported, _, err := readImportMap(base, config.ImportMap); err == nil {
				return imported.Imports, imported.Scopes
			}
		}
		return config.Imports, config.Scopes
	}
	return nil, nil
}

func mappedRemoteSpecifier(spec, source string, imports map[string]string, scopes map[string]map[string]string) string {
	best := ""
	for scope := range scopes {
		if strings.HasPrefix(scope, "https://") && strings.HasPrefix(source, scope) && len(scope) > len(best) {
			best = scope
		}
	}
	if best != "" {
		if mapped, ok := mapInScope(spec, scopes[best]); ok {
			return mapped
		}
	}
	mapped, _ := mapInScope(spec, imports)
	return mapped
}

func resolveRemoteSpecifier(parent, spec string) string {
	base, err := url.Parse(parent)
	if err != nil {
		return ""
	}
	dep, err := url.Parse(spec)
	if err != nil || dep.Scheme != "" && dep.Scheme != "https" || dep.Host != "" && dep.Scheme == "" {
		return ""
	}
	if dep.Scheme == "" && !strings.HasPrefix(spec, "./") && !strings.HasPrefix(spec, "../") && !strings.HasPrefix(spec, "/") {
		return ""
	}
	return base.ResolveReference(dep).String()
}

func remoteImports(source string, data []byte) ([]string, error) {
	loader, ok := sourceLoader(filepath.Ext(strings.SplitN(source, "?", 2)[0]))
	if !ok {
		loader = api.LoaderTS
	}
	result := api.Build(api.BuildOptions{Stdin: &api.StdinOptions{Contents: string(data), Sourcefile: source, Loader: loader}, Bundle: false, TreeShaking: api.TreeShakingFalse, TsconfigRaw: `{"compilerOptions":{"verbatimModuleSyntax":true}}`, Metafile: true, Write: false, Outfile: "out.js", LogLevel: api.LogLevelSilent})
	if len(result.Errors) != 0 {
		return nil, errors.New("remote source parse failed")
	}
	var meta struct {
		Outputs map[string]struct {
			Imports []struct {
				Path string `json:"path"`
				Kind string `json:"kind"`
			} `json:"imports"`
		} `json:"outputs"`
	}
	if err := json.Unmarshal([]byte(result.Metafile), &meta); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var specs []string
	for _, output := range meta.Outputs {
		for _, imp := range output.Imports {
			if imp.Kind != "import-statement" && imp.Kind != "dynamic-import" && imp.Kind != "require-call" || seen[imp.Path] {
				continue
			}
			seen[imp.Path] = true
			specs = append(specs, imp.Path)
		}
	}
	for _, spec := range typeOnlyImportSpecifiers(data) {
		if !seen[spec] {
			seen[spec] = true
			specs = append(specs, spec)
		}
	}
	sort.Strings(specs)
	return specs, nil
}

func validRemoteURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && (u.Port() == "" || u.Port() == "443") && u.User == nil && u.Opaque == "" && u.Fragment == "" && safeurl.Clean(raw) != ""
}

func fetchRemote(ctx context.Context, raw string) ([]byte, string, error) {
	fetch, closeConnections := newRemoteFetcher()
	defer closeConnections()
	return fetch(ctx, raw)
}

func newRemoteFetcher() (remoteFetcher, func()) {
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil || port != "443" {
				return nil, errors.New("unsafe remote address")
			}
			ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, errors.New("remote host unavailable")
			}
			for _, ip := range ips {
				if !publicIP(ip) {
					return nil, errors.New("remote host resolves to a non-public address")
				}
			}
			var dialErr error
			for _, ip := range ips {
				conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				dialErr = err
			}
			return nil, dialErr
		},
	}
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || !validRemoteURL(req.URL.String()) {
			return errors.New("unsafe remote redirect")
		}
		return nil
	}}
	return func(ctx context.Context, raw string) ([]byte, string, error) {
		return fetchWithClient(ctx, client, raw)
	}, transport.CloseIdleConnections
}

func fetchWithClient(ctx context.Context, client *http.Client, raw string) ([]byte, string, error) {
	if !validRemoteURL(raw) {
		return nil, "", errors.New("invalid remote URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("remote HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteFile+1))
	if err != nil || len(data) > maxRemoteFile {
		return nil, "", errors.New("remote source exceeds size limit")
	}
	return data, resp.Request.URL.String(), nil
}

func publicIP(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.Is4In6() {
		return false
	}
	for _, raw := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(raw).Contains(ip) {
			return false
		}
	}
	return true
}
