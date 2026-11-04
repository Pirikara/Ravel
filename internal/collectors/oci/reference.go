package oci

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/Pirikara/Ravel/internal/model"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// CollectReference downloads one platform's image from a registry and then
// scans it through the same verified OCI layout path as a local archive.
func CollectReference(reference, requestedPlatform string) (model.Document, error) {
	platform, err := referencePlatform(requestedPlatform)
	if err != nil {
		return model.Document{}, err
	}
	options := []name.Option{}
	if localRegistry(reference) {
		options = append(options, name.Insecure)
	}
	ref, err := name.ParseReference(reference, options...)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid image reference: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	img, err := remote.Image(ref, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithPlatform(platform))
	if err != nil {
		return model.Document{}, fmt.Errorf("fetch image %s: %w", ref.Name(), err)
	}
	rawManifest, err := img.RawManifest()
	if err != nil {
		return model.Document{}, err
	}
	if len(rawManifest) > maxMetadataBytes {
		return model.Document{}, errors.New("image manifest exceeds OCI metadata limit")
	}
	manifest, err := img.Manifest()
	if err != nil {
		return model.Document{}, err
	}
	if len(manifest.Layers) > maxImageLayers || manifest.Config.Size < 0 || manifest.Config.Size > maxMetadataBytes {
		return model.Document{}, errors.New("image manifest exceeds OCI limits")
	}
	total := manifest.Config.Size
	for _, layer := range manifest.Layers {
		if layer.Size < 0 || layer.Size > maxLayerBytes || total > maxArchiveBytes-layer.Size {
			return model.Document{}, errors.New("image layers exceed OCI download limits")
		}
		if strings.Contains(string(layer.MediaType), "foreign") || strings.Contains(string(layer.MediaType), "nondistributable") {
			return model.Document{}, errors.New("remote foreign image layers are unsupported")
		}
		total += layer.Size
	}
	temp, err := os.MkdirTemp("", "ravel-registry-image-")
	if err != nil {
		return model.Document{}, err
	}
	defer os.RemoveAll(temp)
	imageLayout, err := layout.Write(temp, empty.Index)
	if err != nil {
		return model.Document{}, err
	}
	if err := imageLayout.AppendImage(img, layout.WithPlatform(platform)); err != nil {
		return model.Document{}, fmt.Errorf("download image %s: %w", ref.Name(), err)
	}
	digest, err := img.Digest()
	if err != nil {
		return model.Document{}, err
	}
	selectedPlatform := platform.OS + "/" + platform.Architecture
	if platform.Variant != "" {
		selectedPlatform += "/" + platform.Variant
	}
	doc, err := Collect(temp, path.Base(ref.Context().RepositoryStr()), selectedPlatform)
	if err != nil {
		return model.Document{}, err
	}
	source := ref.Context().Name() + "@" + digest.String()
	doc.Source = source
	doc.Sources = []string{source}
	return doc, nil
}

// CollectDockerReference scans exactly the image stored in the local Docker
// daemon. It never pulls a registry image as a fallback.
func CollectDockerReference(reference, requestedPlatform string) (model.Document, error) {
	if _, err := referencePlatform(requestedPlatform); err != nil {
		return model.Document{}, err
	}
	ref, err := name.ParseReference(reference)
	if err != nil {
		return model.Document{}, fmt.Errorf("invalid image reference: %w", err)
	}
	temp, err := os.CreateTemp("", "ravel-docker-image-*.tar")
	if err != nil {
		return model.Document{}, err
	}
	defer os.Remove(temp.Name())
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "image", "save", reference)
	cmd.Stdout = &sizeLimitedWriter{writer: temp, remaining: maxArchiveBytes}
	var stderr boundedDiagnostic
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	closeErr := temp.Close()
	if runErr != nil {
		message := strings.TrimSpace(stderr.String())
		return model.Document{}, fmt.Errorf("docker image save failed: %w: %s", runErr, message)
	}
	if closeErr != nil {
		return model.Document{}, closeErr
	}
	doc, err := CollectArchive(temp.Name(), path.Base(ref.Context().RepositoryStr()), requestedPlatform)
	if err != nil {
		return model.Document{}, err
	}
	doc.Source = "docker:" + reference
	doc.Sources = []string{doc.Source}
	return doc, nil
}

func referencePlatform(value string) (v1.Platform, error) {
	if value == "" {
		return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}, nil
	}
	if !platformName.MatchString(value) {
		return v1.Platform{}, errors.New("invalid OCI platform; use os/architecture[/variant]")
	}
	parts := strings.Split(value, "/")
	p := v1.Platform{OS: parts[0], Architecture: parts[1]}
	if len(parts) == 3 {
		p.Variant = parts[2]
	}
	return p, nil
}

func localRegistry(reference string) bool {
	host := strings.SplitN(reference, "/", 2)[0]
	return host == "localhost" || strings.HasPrefix(host, "localhost:") || host == "127.0.0.1" || strings.HasPrefix(host, "127.0.0.1:") || host == "[::1]" || strings.HasPrefix(host, "[::1]:")
}

type sizeLimitedWriter struct {
	writer    io.Writer
	remaining int64
}

type boundedDiagnostic struct{ bytes.Buffer }

func (w *boundedDiagnostic) Write(p []byte) (int, error) {
	if w.Len() < 4096 {
		_, _ = w.Buffer.Write(p[:min(len(p), 4096-w.Len())])
	}
	return len(p), nil
}

func (w *sizeLimitedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		return 0, errors.New("Docker image archive exceeds size limit")
	}
	n, err := w.writer.Write(p)
	w.remaining -= int64(n)
	return n, err
}
