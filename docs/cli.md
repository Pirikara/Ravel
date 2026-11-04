# CLI guide

The examples below assume `ravel` is on your `PATH`; see [installation](install.md).

`scan` accepts a supported file, project directory, or container image reference. CycloneDX JSON goes to
stdout unless `--output` is set; progress and errors go to stderr. Run `ravel`
without arguments for command syntax.

`ravel version` (or `ravel --version`) prints the build version. Local source
builds report Go's embedded module or commit version when available, falling
back to `dev`. Release binaries and versioned `go install` builds report their
tagged prerelease version.

## Local paths and remote repositories

`ravel scan` accepts one local path. Point it at a lockfile, package archive,
installed root filesystem, saved container image, or project directory:

```sh
ravel scan ./project/poetry.lock --output poetry.cdx.json --report poetry.coverage.json
ravel scan ./project --output project.cdx.json --report project.coverage.json
```

For a remote Git repository, clone or check out the revision you want, then
scan that local checkout:

```sh
git clone https://github.com/OWNER/PROJECT.git project
git -C project checkout REF
ravel scan project --all --recursive --output project.cdx.json --report project.coverage.json
```

Replace `REF` with a commit or tag for a repeatable scan. Use
`git clone --recurse-submodules` when the inputs you need are in submodules.
`--all --recursive` scans supported static inputs in nested projects; manifests
that need package-manager resolution are reported as skipped. Direct Git URLs
and remote repository archives are not scan inputs. Fetch them locally first.
Ravel does not automatically record the scanned checkout's Git commit ID, so
keep it alongside the generated result.

## Scan workflows

### One project or a polyglot tree

```sh
ravel scan path/to/project --output sbom.cdx.json --report coverage.json
ravel scan path/to/polyglot-project --all --recursive --output combined.cdx.json
```

`--all` combines static inputs in one directory. `--recursive` also scans subprojects while skipping generated directories such as `.git`, `node_modules`, and `vendor`. Archives are not automatically discovered. If multiple JavaScript lockfiles coexist, Ravel uses `package.json`'s `packageManager` field; otherwise select a manager explicitly.

### Repository runtime versions

Repository scans also read explicit runtime declarations. For example:

```sh
ravel scan path/to/repository --all --recursive \
  --format ravel-json --output repository.ravel.json
```

The `runtimes` array records the requested version or range, its meaning (`selection`, `minimum`, `suggested`, or `compatibility`), scope, and source-file evidence. Supported declarations include `.nvmrc`, `.node-version`, `.python-version`, `.ruby-version`, `.tool-versions`, `package.json` `engines.node`, `pyproject.toml` `requires-python`, Go module/workspace directives, Cargo `rust-version`, rustup toolchain files, `.NET` `global.json` SDK selection, `Package.swift` tools version, and Dart/Flutter `pubspec.yaml` constraints. A repository containing only version declarations can also be scanned; its package graph and origin remain `unknown`. If a Go, Cargo, Gradle, or SwiftPM manifest needs package-manager resolution, `--all` can still emit its runtime declarations and records the skipped dependency scan as a coverage issue. Use `--resolve --allow-exec` separately for that graph.

These values describe repository requirements, not the runtime actually installed on a machine or in an image. CycloneDX puts them in root-component `ravel:runtimeRequirement` properties; SPDX puts them in the root package comment. Ravel JSON retains the source evidence.

### A package archive or installed system

```sh
ravel scan path/to/app.jar --output app.cdx.json
ravel scan path/to/package.whl --output wheel.cdx.json
ravel scan path/to/package.nupkg --output nuget.cdx.json
ravel scan path/to/debian-rootfs --manager dpkg --output debian.cdx.json
ravel scan path/to/alpine-rootfs --manager apk --output alpine.cdx.json
ravel scan path/to/fedora-rootfs --manager rpm --output fedora.cdx.json
```

`.war`, `.gem`, and npm `.tgz` archives are also accepted. An archive proves the bytes Ravel read; it does not by itself prove which registry supplied them.

### A container image

```sh
ravel scan ghcr.io/owner/image:tag --platform linux/amd64 \
  --output image.cdx.json --report image.coverage.json
ravel scan image:tag --image-source docker --output local-image.cdx.json
docker save --output image.docker.tar image:tag
ravel scan image.docker.tar --platform linux/amd64 \
  --output image.cdx.json --report image.coverage.json
```

An image reference uses the registry by default, with Docker credential configuration when authentication is required. `--image-source docker` reads only the local Docker daemon. Registry scans select `linux` on the host architecture by default; set `--platform os/architecture[/variant]` for another platform. Ravel records the selected manifest digest as the image source in Ravel JSON. A registry scan requires network access; an explicit `--network deny` is rejected. You can also scan an OCI layout directory, a `.oci.tar` archive, or a gzip-compressed `.docker.tar.gz` / `.oci.tar.gz` archive. For a generic `.tar` or `.tar.gz` file, specify `--manager oci`.

### Inspect, compare, and combine

```sh
ravel scan path/to/project --format ravel-json --output project.ravel.json
ravel explain 'package-name' --input project.ravel.json
ravel diff before.ravel.json after.ravel.json --format json
ravel merge --name my-app --format cyclonedx-json \
  --output combined.cdx.json npm.ravel.json cargo.ravel.json
```

`explain` accepts a package name, PURL, or component ID. If multiple occurrences share a name, use the component ID. `merge` takes at least two Ravel JSON inputs, preserves distinct occurrences, and rejects duplicate input scopes.

### OpenVEX correlation

```sh
ravel scan path/to/project --format ravel-json --output project.ravel.json
ravel vex --input project.ravel.json --vex supplier.openvex.json
ravel vex --input project.ravel.json --vex supplier.openvex.json \
  --format json --output vex-matches.json
```

`vex` reads a local OpenVEX v0.2.0 document. It reports each statement with its issuer, timestamp, vulnerability ID, status, rationale, and products, along with the VEX input's SHA-256 digest. A product matches an SBOM component only when its `@id` PURL or `identifiers.purl` is exactly equal to the component PURL. All matching component IDs are listed with `matchMethod: exact_purl`; unmatched products remain visible with a reason. The issuer's subcomponent PURLs are shown for context but are not correlated to the SBOM. Product IDs based only on hashes, CPEs, or other identifiers remain unmatched. An issuer's status for a dependency does not establish the status of the application that contains it. Ravel does not check signatures, establish the issuer's authority, detect vulnerabilities, or change the SBOM or any vulnerability finding. The output is a correlation report, not a VEX document authored by Ravel.

## Coverage and output formats

| Output | Use it for | Retained detail |
| --- | --- | --- |
| `cyclonedx-json` (default) | A standard CycloneDX 1.7 SBOM | Packages and unconditional dependencies; some provenance details as supported by the format. |
| `spdx-json` | A standard SPDX 2.3 SBOM | Packages, PURLs when established, and unconditional dependencies. |
| `ravel-json` | Investigation, `explain`, `diff`, `merge`, and `enrich` | Evidence, conditional edges, origin and development records, and scan coverage. |
| `--report FILE` | Checking the result of any output format | Scan issues and `outputLosses` for the chosen format. |

`graphState` and `originState` describe the scanned scope:

- `complete_for_scope`: Ravel found no known gap for that dimension **within the input's defined scope**.
- `partial`: Ravel found packages or relationships but also recorded a known gap.
- `unknown`: The input did not establish a graph or origin for that dimension.

`--strict` writes the requested output and then exits with code **3** if any scan coverage issue remains. A normal successful scan exits **0**; scan or input failures exit **1**, and invalid usage exits **2**. `outputLosses` describe conversion to the chosen format and do not by themselves trigger strict mode.

### Coverage report example

The repository includes an RPM database with two test packages:

```sh
ravel scan testdata/fixtures/rpm-sqlite-basic \
  --manager rpm \
  --output rpm.cdx.json \
  --report rpm.coverage.json
```

The report records two packages, their verified dependency, and the remaining origin limit:

```json
{
  "manager": "rpm",
  "graphState": "complete_for_scope",
  "originState": "partial",
  "packages": 2,
  "edges": 3,
  "issues": [
    {"code": "missing_source", "name": "RPM database"}
  ],
  "outputFormat": "cyclonedx-json",
  "outputLosses": [
    {"code": "edge_kinds_omitted", "count": 3},
    {"code": "evidence_records_omitted", "count": 5},
    {"code": "source_paths_omitted", "count": 1},
    {"code": "coverage_issues_omitted", "count": 1}
  ]
}
```

The three Ravel edges include two installed-package edges and one dependency whose RPM version constraint is verified from the installed database's flags and version tags. The dependency is included in CycloneDX.

## Optional resolution and enrichment

A normal `scan` does not execute a package manager. For **Go modules, Cargo, Maven, Gradle, or SwiftPM**, resolution is opt-in:

```sh
ravel scan path/to/cargo/project --manager cargo \
  --resolve --allow-exec --network deny
ravel scan path/to/gradle/project --manager gradle \
  --resolve --allow-exec --configuration runtimeClasspath --network deny
```

`--network deny` is the default for resolver commands. Package manager offline flags do **not** isolate build scripts or plugins at the operating system level. Use `--network allow` only when you intend to permit the resolver to fetch data.

`enrich` is a separate, explicit network operation. It reads Ravel JSON and adds development repository **candidates** from matched registry metadata without changing package identities, distribution origins, or dependency edges:

```sh
ravel enrich scan.ravel.json --ecosystem npm --network allow \
  --output enriched.ravel.json
```

The supported ecosystems are `rubygems`, `npm`, and `pypi`. Ravel checks the package name and version plus the applicable platform, tarball URL, or distribution digest before accepting a repository candidate. `--registry HTTPS_URL` selects an API origin; `--max-requests N` lowers the default 1,000-request limit. Requests use HTTPS, bounded responses and deadlines, and no redirects or credentials. Failed lookups and mismatches appear in coverage.
