# Ravel

**SBOMs that show their work.**

[![CI](https://github.com/Pirikara/Ravel/actions/workflows/ci.yml/badge.svg)](https://github.com/Pirikara/Ravel/actions/workflows/ci.yml)

**Beta** · Go 1.27+

Ravel is a command-line SBOM generator for project lockfiles, package archives, installed systems, and local container images. It produces CycloneDX or SPDX, and lets you trace package and dependency claims back to the input that supports them.

A package name is only part of the story. Ravel also records declared registries and distribution URLs when the input provides them, keeps development repositories separate from download sources, and reports what it could not establish.

## Get started

Build Ravel from source:

```sh
git clone https://github.com/Pirikara/Ravel.git
cd Ravel
go build -o ravel ./cmd/ravel
./ravel scan path/to/project --output sbom.cdx.json --report coverage.json
```

This writes a CycloneDX 1.7 SBOM and a coverage report. Scanning is local and offline by default; Ravel does not run a package manager unless you explicitly opt into resolution.

To inspect the evidence behind a finding, save Ravel's native format:

```sh
./ravel scan path/to/project --format ravel-json --output scan.ravel.json
./ravel explain package-name --input scan.ravel.json
```

Use a component ID with `explain` when the same name appears more than once. See the [CLI guide](docs/cli.md) for all commands and options.

## Why Ravel

| Question | What Ravel records |
| --- | --- |
| What did the input identify? | Package occurrences with names, versions, platform or installation context, and source evidence. |
| How are packages connected? | Dependency and installation edges, including conditions when a target or choice is not settled. |
| Where might a package have come from? | Declared registry or distribution location, distinguished from a development repository. Credentials and URL secrets are removed. |
| What remains uncertain? | A coverage report with specific issues for the scanned scope and information lost in standard-format export. |

Ravel does not turn a lockfile URL into proof of a download. It labels a registry or distribution URL as **declared** unless stronger evidence is available. When the source is unknown, it leaves the claim open.

Try `explain` on the included Poetry fixture to see a declared registry, a dependency, and a remaining graph limit:

```sh
./ravel scan testdata/fixtures/poetry-basic --format ravel-json --output poetry.ravel.json
./ravel explain Requests --input poetry.ravel.json
```

```text
Requests@2.32.3 [poetry:4f5ea5c82373ceb75c4042fe]
origin: declared_registry https://pypi.example.test/simple [declared]
  evidence: poetry-lock testdata/fixtures/poetry-basic/poetry.lock /package/0
required by: poetry-basic
  evidence: poetry-manifest testdata/fixtures/poetry-basic/pyproject.toml /dependencies/requests
depends on: idna@3.10
  evidence: poetry-lock testdata/fixtures/poetry-basic/poetry.lock /package/dependencies/idna
  evidence: poetry-lock testdata/fixtures/poetry-basic/poetry.lock /package/0
coverage: graph=partial origin=complete_for_scope
```

## Supported inputs

| Source | Examples |
| --- | --- |
| Project dependencies | npm, pnpm, Yarn, Bun, Deno, uv, Poetry, PDM, Pipenv, pylock, NuGet, Maven, Gradle, Cargo, Go vendor, SwiftPM, Bundler, Composer, and more. |
| Package archives | JAR/WAR, wheel, npm tarball, NuGet package, and Ruby gem. |
| Installed systems | Debian, Alpine, and RPM package databases; installed Python, Node, Ruby, Composer, Conda, .NET, Java, Go, and Rust metadata in images. |
| Container images | Local OCI layouts and OCI or Docker save archives, with final-layer package and runtime detection. |

The [full input matrix](docs/supported-inputs.md) lists formats and versions. [Known limits](docs/limitations.md) describe cases where a lockfile or installed database cannot establish a complete graph or origin.

## Common workflows

Scan a polyglot repository:

```sh
./ravel scan path/to/repository --all --recursive \
  --output repository.cdx.json --report repository.coverage.json
```

Scan a locally saved container image:

```sh
docker save --output image.docker.tar image:tag
./ravel scan image.docker.tar \
  --output image.cdx.json --report image.coverage.json
```

Ravel reads local image data; it does not pull images. For a multi-platform OCI layout, select a platform with `--platform`.

Compare or combine native scans:

```sh
./ravel diff before.ravel.json after.ravel.json
./ravel merge --name my-app --output combined.cdx.json \
  frontend.ravel.json backend.ravel.json
```

## Output and confidence

| Output | Purpose |
| --- | --- |
| `cyclonedx-json` (default) | CycloneDX 1.7 JSON for downstream SBOM consumers. |
| `spdx-json` | SPDX 2.3 JSON. |
| `ravel-json` | Full evidence, conditional edges, origins, development candidates, and coverage. |
| `--report FILE` | Coverage issues and detail lost when exporting to the selected format. |

Standard SBOM formats contain the relationships Ravel can assert unconditionally for the scan. Keep Ravel JSON when you need to inspect conditional edges or the evidence for a claim. The [evidence model](docs/concepts.md) explains the distinction.

## Beta status

Ravel's results are scoped to the input it scanned. A report marked `complete_for_scope` means no known gap in that dimension **within that scope**; it does not certify an entire application or image. Use `--strict` in automation if a recorded coverage issue should fail the job.

The project has a source-backed integration suite across the [supported inputs](docs/supported-inputs.md). Bug reports and pull requests are welcome; see [contributing](CONTRIBUTING.md) for how to report a scan error and [development](docs/development.md) for test commands.
