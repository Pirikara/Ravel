# Ravel

Ravel is a work in progress SBOM CLI written in Go. It reads lockfiles, selected package manager resolution results, and package archives. It keeps package identities, dependency edges, distribution origins, development repositories, and the evidence for each claim separate. It emits CycloneDX 1.7 JSON, SPDX 2.3 JSON, a detailed Ravel JSON document, and a coverage report.

## Build

```sh
go build -o ravel ./cmd/ravel
```

## Quick start

```sh
./ravel scan path/to/project --output sbom.cdx.json --report coverage.json
./ravel scan path/to/project --format ravel-json --output scan.ravel.json
./ravel scan path/to/project --format spdx-json --output sbom.spdx.json
./ravel scan path/to/polyglot-project --all --recursive --output combined.cdx.json
./ravel scan path/to/project --strict --output sbom.cdx.json

./ravel scan path/to/go/project --manager go --resolve --allow-exec --network deny
./ravel scan path/to/cargo/project --manager cargo --resolve --allow-exec --network deny
./ravel scan path/to/gradle/project --manager gradle --resolve --allow-exec --configuration runtimeClasspath --network deny
./ravel scan path/to/maven/project --manager maven --resolve --allow-exec --network deny
./ravel scan path/to/swift/project --manager swiftpm --resolve --allow-exec --network deny

./ravel scan path/to/package.gem --output package.cdx.json
./ravel scan path/to/package.tgz --output package.cdx.json
./ravel scan path/to/package.whl --output package.cdx.json
./ravel scan path/to/package.nupkg --output package.cdx.json
./ravel scan path/to/app.jar --output app.cdx.json

./ravel merge --name my-app --format cyclonedx-json --output combined.cdx.json npm.ravel.json cargo.ravel.json
./ravel enrich scan.ravel.json --ecosystem rubygems --network allow --output enriched.ravel.json
./ravel enrich scan.ravel.json --ecosystem npm --network allow --output enriched.ravel.json
./ravel enrich scan.ravel.json --ecosystem pypi --network allow --output enriched.ravel.json
./ravel explain 'monolog/monolog' --input scan.ravel.json
./ravel diff before.ravel.json after.ravel.json --format json
```

`scan` accepts a project directory, a supported lockfile or manifest, or a `.jar`, `.war`, `.nupkg`, `.whl`, `.tgz`, or `.gem` archive. Its default output is CycloneDX JSON on stdout. Diagnostics go to stderr. `--strict` returns exit code 3 when coverage issues remain, after writing the requested output.

A normal scan reads local files without running a package manager or making network requests. `--resolve` requires `--allow-exec` and uses the selected manager's offline mode unless `--network allow` is explicit. Offline flags do not isolate build scripts or plugins at the operating system level.

`--all` scans the static inputs in one directory; `--recursive` includes subprojects and skips generated directories such as `.git`, `node_modules`, and `vendor`. Archives are not discovered automatically. When multiple JavaScript lockfiles coexist, Ravel uses `package.json`'s `packageManager` field; an ambiguous selection requires `--manager`. Separate scans can be combined with `merge`.

## Evidence and output

A lockfile registry URL is recorded as a *declared* origin, not proof of a download. A local archive proves its own bytes and metadata, but not which registry supplied it. Ravel omits a default registry PURL when that registry cannot be established. Credentials, URL queries, and fragments are removed before URLs are stored in output.

Ravel JSON retains the evidence, conditional edges, and reasons for incomplete coverage. `explain` looks up a component by name, PURL, or component ID and shows its origins, development repository candidates, dependency edges, and evidence. `diff` compares two Ravel JSON documents. `merge` retains distinct occurrences and rejects duplicate input scopes. CycloneDX and SPDX contain only dependency edges that are unconditional for the scanned scope. The coverage report lists known information losses for the selected output format separately from scan issues; `--strict` applies to scan issues.

## Supported inputs

| Ecosystem | Static inputs and current behavior |
| --- | --- |
| Ruby | `Gemfile.lock` with GEM, GIT, and PATH sources and dependency edges; `.gem` archives with metadata and SHA-256 |
| JavaScript | npm lockfiles v1-v3, pnpm lockfiles v6/v9, Yarn Classic and Berry, Bun text `bun.lock` v0-v2; npm `.tgz` archives |
| Deno | `deno.lock` v4/v5 with configuration and source import discovery for JSR, npm, and URL modules |
| Python | `uv.lock` v1, `pylock.toml` 1.0, Poetry, Pipenv, PDM, pinned pip requirements, and wheel archives |
| .NET | NuGet `packages.lock.json`, `project.assets.json`, and `.nupkg` archives |
| Swift | `Package.resolved` v1-v3; an opt-in SwiftPM resolver supplies package edges |
| Java | Maven `pom.xml` and dependency tree JSON; Gradle lockfiles; JAR/WAR archives and nested JARs |
| Go | `vendor/modules.txt` with `go.mod`; an opt-in `go list` resolver when vendor data is absent |
| Rust | Cargo.lock v3/v4; an opt-in `cargo metadata` resolver for the selected host graph |
| Other | Composer, CocoaPods, and Dart/Flutter Pub lockfiles |

Deno scans JavaScript and TypeScript source files in the project tree as potential entry points. It applies `deno.json` / `deno.jsonc` import aliases and scopes, including a local `importMap` file, and records source-file evidence for locked imports. Generated directories and symlinks are skipped; parse errors and scan limits appear in coverage.

Bun lockfile scans use package locations to distinguish nested versions, check root dependency declarations against `package.json` when present, and keep optional and platform conditions on their edges. Git and URL selectors are kept out of package version fields.

Ravel preserves conditional edges for Python markers and extras, npm peers, NuGet target frameworks, Cargo target and feature choices, CocoaPods target choices, and other unresolved variants. Without a target selection, it does not turn those edges into unconditional CycloneDX or SPDX dependencies.

Several formats have intentional limits. Binary `bun.lockb` is rejected explicitly. npm v1 requires `package.json` to identify direct dependencies, and nested packages without a `requires` map cannot establish transitive edges. Deno source scanning covers static imports, re-exports, and literal dynamic imports, while computed imports and runtime-selected entry points remain partial. Static SwiftPM pins do not establish dependency edges. Gradle lockfiles provide selected versions but not dependency edges. Maven and Gradle resolvers currently cover the root project; child modules and projects remain partial. Go vendor data and Pub lockfiles do not provide complete transitive edges. Poetry and Composer manifest freshness is not verified. These limitations appear in coverage rather than being filled with guesses.

## Registry metadata enrichment

`enrich` reads Ravel JSON and requires `--network allow`. It adds development repository *candidates*; it does not change package identities, distribution origins, or dependency edges. Use `--registry HTTPS_URL` to select a registry API origin, and `--max-requests N` to lower the default limit of 1,000 requests. Requests use HTTPS, a five second timeout, a 2 MiB response limit, and a two minute overall deadline. Redirects and credentials are not used. The response SHA-256 and observation time are recorded with each candidate.

- `--ecosystem rubygems`: Queries version metadata only when a Bundler package has one GEM remote matching the selected registry. It verifies name, version, and platform before accepting `metadata.source_code_uri`.
- `--ecosystem npm`: Supports npm, pnpm, Bun, and Yarn lockfile occurrences with one tarball URL under the selected registry. It verifies name, version, and `dist.tarball` before accepting `repository`.
- `--ecosystem pypi`: Supports uv and pylock occurrences with a matching `/simple` index and one retained distribution SHA-256. It verifies the normalized name, version, and release file digest before accepting a source or repository entry from `project_urls`. Packages without a retained digest are not enriched.

The default registries are `https://rubygems.org`, `https://registry.npmjs.org`, and `https://pypi.org` respectively. The default `enrich` output is Ravel JSON; `--format cyclonedx-json` and `--format spdx-json` are also available. Failed requests, mismatches, and missing or unsafe repository URLs are reported as coverage issues.

## Development and tests

```sh
go test ./...
go vet ./...
```

The integration suite scans 162 supported fixture directories and 24 unsupported format cases. It validates CycloneDX 1.7 and SPDX 2.3 against their JSON Schemas, checks package and edge counts, and tests provenance, URL redaction, conditional edges, and the CLI reports. Fixtures include lockfiles generated by npm, pnpm, Yarn, Bundler, Composer, Bun, Deno, uv, and dotnet. Archive fixtures include a NuGet package, wheel, npm tarball, Ruby gem, and generated JAR/WAR samples.

The opt-in resolver tests use local dependencies and offline execution where possible. To include the real Maven plugin test, run:

```sh
RAVEL_TEST_REAL_MAVEN=1 go test ./integration -run TestMavenResolverWithRealMaven -count=1
```

Registry enrichment tests use local TLS servers and saved version responses for RubyGems `rack` 3.1.0, npm `is-number` 7.0.0, and PyPI `idna` 3.10. They verify evidence, registry selection, identity checks, artifact matching, and opt-in network access.
