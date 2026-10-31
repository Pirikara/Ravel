# Ravel

**SBOM generation grounded in evidence from projects, archives, and container images.**

[![CI](https://github.com/Pirikara/Ravel/actions/workflows/ci.yml/badge.svg)](https://github.com/Pirikara/Ravel/actions/workflows/ci.yml)

Ravel is a command-line tool under active development, written in Go. It turns local lockfiles, package metadata, archives, and OCI images into a software bill of materials (SBOM). Every package and relationship can carry evidence, while a separate coverage report explains what the input could not establish.

Ravel distinguishes **package identity**, **distribution origin**, and **development repository**. A repository URL in a lockfile is a declaration; it is not proof that a package was downloaded from that URL. When an input cannot establish a claim, Ravel leaves it open instead of inventing one.

- **Outputs:** CycloneDX 1.7 JSON, SPDX 2.3 JSON, Ravel JSON, and a coverage report.
- **Inputs:** common application lockfiles, selected package manager results, package archives, installed OS databases, and local OCI or Docker save archives.
- **Default behavior:** local, static analysis without package manager execution or network access.
- **Inspection:** `explain` a package, `diff` two scans, `merge` scans, or explicitly `enrich` development repository candidates.

> Ravel is under active development. Read the coverage report before treating an SBOM as complete for your use case.

## Contents

- [Get started](#get-started)
- [How Ravel represents evidence](#how-ravel-represents-evidence)
- [Supported inputs](#supported-inputs)
- [Scan workflows](#scan-workflows)
- [Coverage and output formats](#coverage-and-output-formats)
- [Optional resolution and enrichment](#optional-resolution-and-enrichment)
- [Current limits](#current-limits)
- [Development](#development)

## Get started

Ravel currently builds from source and requires **Go 1.27 or newer**.

```sh
go build -o ravel ./cmd/ravel
./ravel scan path/to/project --output sbom.cdx.json --report coverage.json
```

The scan command produces a CycloneDX SBOM and a separate JSON coverage report. To retain evidence and conditional dependency edges for inspection, also write Ravel JSON:

```sh
./ravel scan path/to/project --format ravel-json --output scan.ravel.json
./ravel explain 'package-name' --input scan.ravel.json
```

`scan` accepts either a project directory or a supported file. It writes CycloneDX JSON to stdout unless `--output` is given. Progress and errors go to stderr. Run `./ravel` without arguments for command syntax.

### A small example

The repository includes an RPM database with two test packages. Scan it and inspect the report:

```sh
./ravel scan testdata/fixtures/rpm-sqlite-basic \
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

## How Ravel represents evidence

```mermaid
flowchart LR
  A["Lockfiles and manifests"] --> C["Collectors"]
  B["Archives and installed databases"] --> C
  I["OCI image layers"] --> C
  C --> R["Ravel evidence graph"]
  R --> X["CycloneDX 1.7"]
  R --> Y["SPDX 2.3"]
  R --> Z["Ravel JSON + coverage"]
```

A Ravel JSON document keeps these records separate:

| Record | What it means |
| --- | --- |
| **Component** | One observed package occurrence, with its name, version, context, and evidence. |
| **Edge** | A relationship backed by evidence. A `condition` marks a relationship that depends on an unselected target, range, marker, or other unresolved choice. |
| **Origin** | A distribution location or source declaration, with its evidence and status. |
| **Development** | A candidate source repository. It is distinct from the place that distributed the package. |
| **Coverage** | Package and edge counts, graph and origin states, and specific issues. |

Ravel records hashes for observed archive bytes and checks available lockfile integrity data. It removes credentials, URL queries, and fragments before storing URLs. A default registry Package URL (PURL) is omitted when that registry cannot be established from the input.

CycloneDX and SPDX exports include only dependency edges that are unconditional for the scanned scope. **Ravel JSON retains conditional edges and their evidence**. The coverage report lists any information lost in the requested export separately from scan issues.

## Supported inputs

The table describes inputs Ravel reads today. A listed format does not imply complete dependency or origin coverage; the report describes each scan's actual scope.

| Ecosystem | Inputs | Notes |
| --- | --- | --- |
| Ruby | `Gemfile.lock`; `.gem` archives | GEM, GIT, and PATH sources; archive metadata and SHA-256. |
| JavaScript | npm lockfiles v1–v4; pnpm v6/v9; Yarn Classic and Berry; Bun text `bun.lock` v0–v2; npm `.tgz` archives | Package locations, dependency edges, and conditions where the format permits. |
| Deno | `deno.lock` v4/v5, `deno.json` / `deno.jsonc`, local import maps, JS/TS imports | Discovers static imports, re-exports, and literal dynamic imports as entry points. |
| Python | `uv.lock` v1; `pylock.toml` 1.0; Poetry, Pipenv, PDM, and pinned requirements; `.whl` archives | Keeps markers, extras, groups, and unresolved choices conditional. |
| .NET | NuGet `packages.lock.json`, `project.assets.json`, `.nupkg` archives | Keeps target framework choices. |
| Swift | `Package.resolved` v1–v3 | Static pins do not establish package dependency edges. |
| Java | Maven `pom.xml` and dependency tree JSON; Gradle lockfiles; JAR/WAR archives | Includes declared Maven modules and nested JARs when identifiable. |
| Go | `vendor/modules.txt` with `go.mod` | An optional `go list` resolver handles projects without usable vendor data. |
| Rust | Cargo.lock v3/v4 | An optional `cargo metadata` resolver supplies a selected host graph. |
| PHP | `composer.lock` | Source and distribution URLs remain separate. |
| Apple | CocoaPods `Podfile.lock` | Keeps subspec and target choices. |
| Dart/Flutter | `pubspec.lock` | Hosted, Git, path, and SDK sources are distinguished. |

### Installed systems and images

| Input | Current scope |
| --- | --- |
| Debian rootfs | Installed packages from `var/lib/dpkg/status`; declared `Depends` and `Pre-Depends`. |
| Alpine rootfs | APK text v2 `lib/apk/db/installed` and binary v3 `lib/apk/db/installed.adb` (plain, deflate, or zstd); installed names and supported virtual providers. |
| RPM rootfs | SQLite `rpmdb.sqlite`, NDB `Packages.db`, and Berkeley DB `Packages`; name, epoch, version, release, architecture, capability links verified where the dependency tags settle the constraint, and exact file-path requirements linked through database ownership. |
| OCI image | Local OCI layout or OCI/Docker save tar archive, including gzip-compressed tar; final Debian, APK, or RPM database, JAR/WAR files, and Go ELF build information after layer whiteouts. |
| Installed Python in OCI | `.dist-info/METADATA`, directory `.egg-info/PKG-INFO`, and legacy single-file `.egg-info` records; `Requires-Dist` and legacy `requires.txt` links when identifiable; packages explicitly listed in pip's installed `_vendor/vendor.txt`; CPython versions embedded in `/usr/local/lib/libpython*.so*` ELF files. |
| Installed Composer in OCI | Conventional `vendor/composer/installed.json` records from Composer 1 and 2; installed package names and versions, with same-registry requirement links when identifiable. |
| Installed Node in OCI | Conventional `node_modules/*/package.json` records and dependency links when identifiable; pnpm virtual-store packages reached by package symlinks in the final image; versioned Yarn installations under `/opt/yarn-v*/package.json`; Node.js runtime versions embedded in `/usr/local/bin/node` ELF executables, checked against `node_version.h` when installed. |
| Installed Ruby in OCI | Generated gemspecs under conventional Ruby gem homes and `/usr/local/bundle`, including default gems. Identity comes from matching stub, literal name/version, and filename. Runtime dependency calls are linked when a numeric version requirement selects one gem in the same home; activation and distribution origin remain unknown. CRuby versions are also read from the exported `ruby_version` symbol in `/usr/local/lib/libruby.so.*` ELF libraries. |
| Java archives in OCI | JAR/WAR files and identifiable nested JARs, with archive hashes and embedded Maven metadata. |
| Go binaries in OCI | Embedded Go toolchain and module versions from Linux ELF files, tied to the executable's SHA-256 and image layer. The module-to-module dependency graph is not reconstructed. |

OCI scans accept OCI and Docker schema 2 media types, verify available descriptor SHA-256 hashes and uncompressed layer DiffIDs. A multi-image layout requires `--platform os/architecture[/variant]`. Legacy Docker save archives must contain one image. Ravel reads local image data; it does not pull images.

## Scan workflows

### One project or a polyglot tree

```sh
./ravel scan path/to/project --output sbom.cdx.json --report coverage.json
./ravel scan path/to/polyglot-project --all --recursive --output combined.cdx.json
```

`--all` combines static inputs in one directory. `--recursive` also scans subprojects while skipping generated directories such as `.git`, `node_modules`, and `vendor`. Archives are not automatically discovered. If multiple JavaScript lockfiles coexist, Ravel uses `package.json`'s `packageManager` field; otherwise select a manager explicitly.

### A package archive or installed system

```sh
./ravel scan path/to/app.jar --output app.cdx.json
./ravel scan path/to/package.whl --output wheel.cdx.json
./ravel scan path/to/package.nupkg --output nuget.cdx.json
./ravel scan path/to/debian-rootfs --manager dpkg --output debian.cdx.json
./ravel scan path/to/alpine-rootfs --manager apk --output alpine.cdx.json
./ravel scan path/to/fedora-rootfs --manager rpm --output fedora.cdx.json
```

`.war`, `.gem`, and npm `.tgz` archives are also accepted. An archive proves the bytes Ravel read; it does not by itself prove which registry supplied them.

### A container image

```sh
docker save --output image.docker.tar image:tag
./ravel scan image.docker.tar --platform linux/amd64 \
  --output image.cdx.json --report image.coverage.json
```

You can also scan an OCI layout directory, a `.oci.tar` archive, or a gzip-compressed `.docker.tar.gz` / `.oci.tar.gz` archive. For a generic `.tar` or `.tar.gz` file, specify `--manager oci`.

### Inspect, compare, and combine

```sh
./ravel scan path/to/project --format ravel-json --output project.ravel.json
./ravel explain 'package-name' --input project.ravel.json
./ravel diff before.ravel.json after.ravel.json --format json
./ravel merge --name my-app --format cyclonedx-json \
  --output combined.cdx.json npm.ravel.json cargo.ravel.json
```

`explain` accepts a package name, PURL, or component ID. If multiple occurrences share a name, use the component ID. `merge` takes at least two Ravel JSON inputs, preserves distinct occurrences, and rejects duplicate input scopes.

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

## Optional resolution and enrichment

A normal `scan` does not execute a package manager. For **Go modules, Cargo, Maven, Gradle, or SwiftPM**, resolution is opt-in:

```sh
./ravel scan path/to/cargo/project --manager cargo \
  --resolve --allow-exec --network deny
./ravel scan path/to/gradle/project --manager gradle \
  --resolve --allow-exec --configuration runtimeClasspath --network deny
```

`--network deny` is the default for resolver commands. Package manager offline flags do **not** isolate build scripts or plugins at the operating system level. Use `--network allow` only when you intend to permit the resolver to fetch data.

`enrich` is a separate, explicit network operation. It reads Ravel JSON and adds development repository **candidates** from matched registry metadata without changing package identities, distribution origins, or dependency edges:

```sh
./ravel enrich scan.ravel.json --ecosystem npm --network allow \
  --output enriched.ravel.json
```

The supported ecosystems are `rubygems`, `npm`, and `pypi`. Ravel checks the package name and version plus the applicable platform, tarball URL, or distribution digest before accepting a repository candidate. `--registry HTTPS_URL` selects an API origin; `--max-requests N` lowers the default 1,000-request limit. Requests use HTTPS, bounded responses and deadlines, and no redirects or credentials. Failed lookups and mismatches appear in coverage.

## Current limits

- **Static data has boundaries.** SwiftPM pins and Gradle lockfiles do not contain complete dependency graphs. Go vendor data and Pub lockfiles do not establish every transitive edge. Maven POMs are not effective POMs, and Poetry/Composer manifest freshness is not verified.
- **Some choices remain conditional.** Python markers and extras, npm peers, NuGet target frameworks, Cargo features and targets, and CocoaPods targets can require an environment or target selection. These edges remain in Ravel JSON and are omitted from unconditional standard-format dependency lists.
- **Installed OS databases do not prove repository origin.** Debian, APK, and RPM scans leave PURL and origin unset when the database cannot establish them. RPM installed headers provide dependency flags and versions. Ravel checks exact version offers using well-formed ASCII RPM EVRs, including epoch, release, letter and number segments, tilde, and caret; a requirement without a release compares against the provider's version. Range offers, missing dependency flags, and a provider's omitted release remain conditional. RPM file-path requirements use exact database ownership; ghost and missing-ok records, symlink aliases, and actual filesystem presence are not inferred from the database. A single unnested `(A if B)` or `(A if B else C)` requirement is evaluated when the guard's installed status can be established; other Boolean expressions remain unresolved. File ownership inspection is limited to one million records. APK v3 installed databases support plain ADB, legacy deflate, and custom deflate or zstd compression within a bounded input size.
- **OCI language coverage is still partial.** Installed Python dist-info, directory egg-info, and single-file egg-info metadata, legacy `requires.txt` dependencies, pip vendor manifests, CPython shared libraries under `/usr/local/lib`, Composer `installed.json`, conventional Node package manifests, pnpm virtual-store manifests reached by package symlinks, the Node.js `/usr/local/bin/node` ELF executable, installed Ruby gemspecs and CRuby shared libraries, JAR/WAR files, and Go ELF build information are read. Legacy `requires.txt` extra and environment sections remain conditional; unsupported or oversized sidecars leave the graph partial. Other language packages and pnpm's global content-addressable store are not yet inventoried from image files. Unlinked pnpm virtual-store entries are reported instead of counted as installed packages. Pip's vendor manifest identifies bundled versions but does not establish the module-to-module graph or distribution origin. Node package directory symlinks are followed only when they reach a recognized manifest within the final image; symlinked runtime executables, Java archives, and Ruby gemspecs are not followed. Java archive inspection is capped at 128 MiB per file, 256 MiB per image, and 1,000 files. CPython and CRuby library inspection is capped at 32 MiB per file and 128 MiB per layer. Node.js executable inspection streams at most 256 MiB per file; installed version headers are capped at 64 KiB. Python egg-info requirements are capped at 256 KiB and 1,024 lines per file, and 8 MiB and 100,000 lines per image. Composer installed manifests are capped at 16 MiB per file, 64 MiB and 100 files per image. Ruby gemspec inspection is capped at 1 MiB per file, 64 MiB and 5,000 files per image. Go ELF inspection is capped at 64 MiB per file, 512 MiB and 1,000 files per layer, and 10,000 tracked files per image; skipped or malformed candidates appear in coverage.
- **Composer installed metadata is a registry snapshot.** The conventional vendor manifest establishes recorded package identity, not the presence of each package file or its distribution origin. Ravel does not follow `install-path`. Version constraints and virtual providers remain conditional, and custom vendor directories are not yet discovered.
- **Some input versions are unsupported.** Binary `bun.lockb` is rejected; create a text `bun.lock` with Bun before scanning. Unknown lockfile versions and unparsed features are reported or rejected rather than silently guessed.

## Development

```sh
go test ./... -count=1
go vet ./...
```

The integration suite scans 186 supported fixture directories and 25 unsupported format cases. It validates CycloneDX 1.7 and SPDX 2.3 against their JSON Schemas and checks package counts, dependency edges, provenance, URL redaction, conditional relationships, and coverage. Fixtures include generated npm, pnpm, Yarn, Bundler, Composer, Bun, Deno, uv, and dotnet lockfiles; Debian, APK (including a converted v3 database from an Alpine image), and RPM installed databases; package archives; and OCI images with a Linux Go executable built for the test.

The [source-reviewed comparison corpus](comparison/README.md) adds package, graph, and unknown-origin assertions over eleven representative fixtures. It can triage CycloneDX differences with other scanners, while source evidence determines the expected result.

The real Maven resolver tests are opt-in:

```sh
RAVEL_TEST_REAL_MAVEN=1 go test ./integration \
  -run 'TestMavenResolverWithReal(Reactor|Maven)' -count=1
```

Registry enrichment tests use local TLS servers and saved version responses. New collectors should include representative real-format fixtures and assertions about identity, graph, origin, and output loss.

See [third-party notices](THIRD_PARTY_NOTICES.md) for licenses of the bundled RPM database reader and zstd decoder.
