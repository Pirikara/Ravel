# Ravel

**SBOMs that show their work.**

[![CI](https://github.com/Pirikara/Ravel/actions/workflows/ci.yml/badge.svg)](https://github.com/Pirikara/Ravel/actions/workflows/ci.yml)

**Beta** · Binaries for macOS, Linux, and Windows · Go 1.27+ for source builds

Ravel is a command-line SBOM generator for project lockfiles, package archives, installed systems, and container images. It produces CycloneDX or SPDX, and lets you trace package and dependency claims back to the input that supports them.

A package name is only part of the story. Ravel also records declared registries and distribution URLs when the input provides them, keeps development repositories separate from download sources, and reports what it could not establish.

## Install

Choose a tag from [GitHub Releases](https://github.com/Pirikara/Ravel/releases), then download its archive for your platform:

| Platform | Archive |
| --- | --- |
| macOS Apple silicon | `ravel_<TAG>_darwin_arm64.tar.gz` |
| macOS Intel | `ravel_<TAG>_darwin_amd64.tar.gz` |
| Linux x86-64 | `ravel_<TAG>_linux_amd64.tar.gz` |
| Linux ARM64 | `ravel_<TAG>_linux_arm64.tar.gz` |
| Windows x86-64 | `ravel_<TAG>_windows_amd64.zip` |

Verify the archive against `SHA256SUMS`, extract it, and put `ravel` (or `ravel.exe`) on your `PATH`. The [install guide](docs/install.md) has commands for each OS. On macOS and Linux, `brew install pirikara/tap/ravel` installs the current release binary. With Go 1.27+, run `go install github.com/Pirikara/Ravel/cmd/ravel@<TAG>` after replacing `<TAG>` with a release tag.

## Get started

Scan a project directory or a specific lockfile:

```sh
ravel scan path/to/project --output sbom.cdx.json --report coverage.json
ravel scan path/to/project/poetry.lock --output poetry.cdx.json --report poetry.coverage.json
```

Each command writes a CycloneDX 1.7 SBOM and a coverage report. Scanning is local and offline by default; Ravel does not run a package manager unless you explicitly opt into resolution.

Run `ravel version` to identify the build you are using.

Use `ravel update --check` to check for a new version, or `ravel update` to install it. A directly installed macOS or Linux release binary can update itself, and a Homebrew installation upgrades through Homebrew. Go and container installations receive the appropriate update command.

`scan` reads a local file or directory, or fetches a Git repository at an explicit revision:

```sh
ravel scan https://github.com/OWNER/PROJECT.git --git-ref refs/heads/main \
  --network allow --all --recursive \
  --output project.cdx.json --report project.coverage.json
ravel scan ssh://git@github.com/OWNER/PROJECT.git --git-ref refs/heads/main \
  --network allow --all --recursive --output private-project.cdx.json
```

The result records the resolved commit. Local checkout scans record their current commit and whether the worktree is dirty. A container image reference such as `image:tag` is pulled from its registry, or from the local Docker daemon with `--image-source docker`. See the [CLI guide](docs/cli.md) for limits and examples.

Use `--git-submodules` with `--all --recursive` to include first-level submodules pinned by the parent repository. Ravel records each submodule's commit and URL separately.

To inspect the evidence behind a finding, save Ravel's native format:

```sh
ravel scan path/to/project --format ravel-json --output scan.ravel.json
ravel explain package-name --input scan.ravel.json
ravel graph --input scan.ravel.json --format html --output dependencies.html
```

Open `dependencies.html` in a browser to inspect the recorded dependency graph offline. Use a component ID with `explain` or `graph --focus` when the same name appears more than once. See the [CLI guide](docs/cli.md) for all commands and options.

To compare an externally issued OpenVEX document with a scan, use `ravel vex`:

```sh
ravel vex --input scan.ravel.json --vex advisory.openvex.json --format json
```

The result identifies exact PURL matches and retains the issuer's status and rationale. Ravel does not scan for vulnerabilities or issue VEX conclusions. See [VEX correlation](docs/cli.md#openvex-correlation) for the matching rules and limits.

## Why Ravel

| Question | What Ravel records |
| --- | --- |
| What did the input identify? | Package occurrences with names, versions, platform or installation context, and source evidence. |
| How are packages connected? | Dependency and installation edges, including conditions when a target or choice is not settled. |
| Where might a package have come from? | Declared registry or distribution location, distinguished from a development repository. Credentials and URL secrets are removed. |
| What remains uncertain? | A coverage report with specific issues for the scanned scope and information lost in standard-format export. |

Ravel does not turn a lockfile URL into proof of a download. It labels a registry or distribution URL as **declared** unless stronger evidence is available. When the source is unknown, it leaves the claim open.
When a pnpm, Bun, NuGet, Composer, or Deno npm lock entry identifies an ecosystem package but omits its registry, Ravel emits an ecosystem PURL with `purlBasis: ecosystem_inferred`. CycloneDX carries this as `ravel:purlBasis`; SPDX records it in the package comment. The PURL does not verify which registry supplied the package. Ravel retains any declared distribution URL and reports a missing source when no such URL is available. Entries with explicit private distribution URLs and local dependencies are handled separately.

To reproduce this example, clone the repository and scan its Poetry fixture. It shows a declared registry, a dependency, and a remaining graph limit:

```sh
git clone https://github.com/Pirikara/Ravel.git
cd Ravel
ravel scan testdata/fixtures/poetry-basic --format ravel-json --output poetry.ravel.json
ravel explain Requests --input poetry.ravel.json
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
| Project dependencies | npm, pnpm, Yarn, Bun, Deno, uv, Poetry, PDM, Pipenv, pylock, NuGet, Maven, Gradle, Cargo, Go modules, SwiftPM, Bundler, source Ruby gemspecs, GitHub Actions workflows, Composer, and more. |
| Repository runtime declarations | Node, Python, Ruby, Go, Rust, Swift tools, Dart, Flutter, and .NET SDK version requirements from common project files. |
| Package archives | Debian `.deb`/`.udeb`/`.ddeb`, RPM `.rpm`, JAR/WAR, wheel, npm tarball, NuGet package, and Ruby gem. |
| Installed systems | Debian, Alpine, and RPM package databases; installed Python, Node, Ruby, Composer, Conda, .NET, Java, Go, and Rust metadata in images. |
| Container images | Registry image references, local Docker images, OCI layouts, and OCI or Docker save archives, with final-layer package and runtime detection. |

The [full input matrix](docs/supported-inputs.md) lists formats and versions. [Known limits](docs/limitations.md) describe cases where a lockfile or installed database cannot establish a complete graph or origin.

## Common workflows

Scan a polyglot repository:

```sh
ravel scan path/to/repository --all --recursive \
  --output repository.cdx.json --report repository.coverage.json
```

Use `--format ravel-json` to inspect the `runtimes` array with each declaration's source and SHA-256 evidence. These are repository requirements or version selections, not proof of the runtime installed in a deployment.

Scan an image directly from a registry:

```sh
ravel scan ghcr.io/owner/image:tag --platform linux/amd64 \
  --output image.cdx.json --report image.coverage.json
```

The image is pulled for the selected platform. Ravel uses your Docker credential configuration for private registries and records the resolved manifest digest in Ravel JSON. To scan an image that exists only in the local Docker daemon, add `--image-source docker`:

```sh
ravel scan image:tag --image-source docker --output image.cdx.json
```

For CI, the same CLI is available as a Linux container. Mount a project directory and select your user ID so output files remain writable:

```sh
tag=YOUR_RELEASE_TAG
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" "ghcr.io/pirikara/ravel:${tag}" \
  scan . --all --recursive --output sbom.cdx.json
```

The container includes the release binary and its licenses. Package-manager resolution requires the corresponding tools, so use the native binary for `--resolve --allow-exec` workflows.

You can also scan a saved container image:

```sh
docker save --output image.docker.tar image:tag
ravel scan image.docker.tar \
  --output image.cdx.json --report image.coverage.json
```

For a multi-platform OCI layout, select a platform with `--platform`. A registry scan defaults to `linux` on the host architecture when no platform is specified.

Compare or combine native scans:

```sh
ravel diff before.ravel.json after.ravel.json
ravel merge --name my-app --output combined.cdx.json \
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

## License

Ravel is licensed under the [Apache License, Version 2.0](LICENSE). Third-party notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
