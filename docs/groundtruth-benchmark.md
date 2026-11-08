# Ground-truth checks

Ravel has three complementary checks for package detection accuracy:

1. The checked-in [DeepBits fixtures](../testdata/groundtruth/deepbits/README.md) run in the integration suite. They compare package name/version multisets, 101 Composer dependency edges, and declared origins where the reference provides them.
2. `scripts/groundtruth_bbp.py` checks five fixed, local BBP snapshots against their package-manager lock records: npm, Cargo, Composer, NuGet, and SwiftPM. The snapshots and generated results stay under the ignored `comparison/` directory.
3. `scripts/groundtruth_images.py` runs `apk`, `dpkg-query`, `pip`, RubyGems, Conda, npm, and Composer's runtime `InstalledVersions` API inside seven locally cached images, then scans the same Docker images with Ravel. It also checks pip's embedded `vendor.txt`, Conda build strings and recorded archive URLs via `conda list --explicit`, npm's global installation paths, and the Python, Redis, Ruby, Node, and PHP runtime versions. Image IDs are recorded so mutable tags cannot silently stand in for the same sample.

Run the checked-in cases with `go test ./integration -run TestDeepBitsGroundtruth -count=1 -v`. To repeat the local BBP check, build the current binary and run:

```sh
go build -o /tmp/ravel-groundtruth ./cmd/ravel
python3 scripts/groundtruth_bbp.py --ravel /tmp/ravel-groundtruth > comparison/bbp-audit/groundtruth-results.json
```

Add `--compare-existing` to score the saved Syft and Trivy CycloneDX outputs from the same snapshots. The script reports both package placements and distinct name/version coordinates. It normalizes npm scopes from PURLs, NuGet name case, and Swift identity paths. These saved outputs represent the pinned tool versions used in the BBP audit; the command does not rerun those tools.

For an independent installed-package check, first ensure `nginx:alpine`, `redis:7-alpine`, `python:3.13-slim`, `ruby:3.3.10-slim`, `continuumio/miniconda3:latest`, `node:24-bookworm-slim`, and `phpmyadmin:latest` are already present in the local Docker daemon. Then run:

```sh
python3 scripts/groundtruth_images.py --ravel /tmp/ravel-groundtruth > comparison/groundtruth-images/results.json
```

The image script runs the package-manager commands with no network and a 512 MiB memory limit per container. Add `--compare-saved` only when Syft and Trivy CycloneDX outputs named `<image>-syft.cdx.json` and `<image>-trivy.cdx.json`, plus a `manifest.json` containing their SHA-256 digests, tool versions, image IDs, and architectures, are present in `comparison/groundtruth-images/`. The script rejects mismatched image IDs, architectures, or saved SBOM digests. Pip's installed distributions and its embedded vendored packages are separate populations; for saved tools their scores measure recall within each known population, since CycloneDX does not reliably distinguish the two. The Conda comparison requires Conda identity; matching PyPI names and versions are reported separately because they do not establish a Conda build or origin. The explicit Conda URLs are recorded locators, not proof that the archive bytes remain installed or match the original download.

For Node, npm's JSON tree repeats shared dependencies, so the script checks distinct name/version coordinates and separately checks each global installation path from `npm ls --parseable`. Ravel's Yarn installation under `/opt` is outside npm's global tree. Saved CycloneDX outputs are image-wide, so their npm scores may include this legitimate extra package. npm package identity is read from the PURL because CycloneDX display names can omit the scope. For Composer, the runtime API may register the same `installed.php` data twice; the check deduplicates records, excludes the root application and virtual provides, and compares installed dependency coordinates. This validates Composer's runtime inventory against Ravel's reading of `installed.json`, but does not prove the package files' contents.

Python 3.11 or newer is required for the BBP script. Its source of truth is each snapshot's lockfile. The script counts repeated package placements separately, excludes the root project from external package counts, and compares NuGet IDs without case. It checks origin URLs only where the lock records them. NuGet's `packages.lock.json` has no registry URL to verify. All URLs from a lockfile are **declared**, not evidence of a completed download.

The checks answer a narrow question: whether Ravel faithfully emits the package identities, selected edges, and source claims supported by these inputs. They do not measure recall for a complete repository or built image, validate license data, or prove that a declared dependency was installed. A broader precision/recall estimate needs independently observed install or build inventories and annotated negative cases for each input scope. Counts from Syft or Trivy are useful discrepancy leads, but are not ground truth.
