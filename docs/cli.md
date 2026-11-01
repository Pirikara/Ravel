# CLI guide

`scan` accepts a supported file or project directory. CycloneDX JSON goes to
stdout unless `--output` is set; progress and errors go to stderr. Run `ravel`
without arguments for command syntax.

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

### Coverage report example

The repository includes an RPM database with two test packages:

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
