# Supported inputs

The table describes inputs Ravel reads today. A listed format does not imply complete dependency or origin coverage; the report describes each scan's actual scope.

Repository directories also expose explicit runtime requirements from `.nvmrc`, `.node-version`, `.python-version`, `.ruby-version`, `.tool-versions`, `package.json` `engines.node`, `pyproject.toml` `requires-python` and Poetry's Python requirement, `go.mod` / `go.work` `go` and `toolchain`, Cargo `rust-version`, `rust-toolchain` / `rust-toolchain.toml`, `.NET` `global.json` SDK version, `Package.swift` tools version, and `pubspec.yaml` Dart/Flutter SDK constraints. These are declarations, not verified installed runtime versions.

| Ecosystem | Inputs | Notes |
| --- | --- | --- |
| Ruby | `Gemfile.lock`; `.gem` archives | GEM, GIT, and PATH sources; archive metadata and SHA-256. |
| JavaScript | npm lockfiles v1–v4; pnpm v6/v9; Yarn Classic and Berry; Bun text `bun.lock` v0–v2; npm `.tgz` archives | Package locations, dependency edges, and conditions where the format permits. |
| Deno | `deno.lock` v4/v5, `deno.json` / `deno.jsonc`, local import maps, JS/TS imports | Discovers static imports, re-exports, and literal dynamic imports as entry points. |
| Python | `uv.lock` v1; `pylock.toml` 1.0; Poetry, Pipenv, PDM, and pinned requirements; `.whl` archives | Keeps markers, extras, groups, and unresolved choices conditional. |
| .NET | NuGet `packages.lock.json`, `project.assets.json`, legacy `packages.config`, `.nupkg` archives | Keeps target framework choices; `packages.config` is a flat project list. |
| Swift | `Package.resolved` v1–v3 | Static pins do not establish package dependency edges. |
| Java / Scala | Maven `pom.xml` and dependency tree JSON; Gradle lockfiles; sbt `*.sbt.lock` v1; JAR/WAR archives | Includes declared Maven modules and nested JARs when identifiable. sbt configurations and safe default JAR checksums are retained. |
| Go | `go.mod` declarations or `vendor/modules.txt` with `go.mod` | The main module is an application component, with a versionless Go PURL for a canonical public module path; repository checkouts do not establish its release version. Static `go.mod` scanning lists declared dependency modules and direct requirements, with selection and transitive graph marked partial. An optional `go list` resolver can verify selected dependency modules. |
| Rust | Cargo.lock v3/v4 | An optional `cargo metadata` resolver supplies a selected host graph. |
| PHP | `composer.lock` | Source and distribution URLs remain separate. |
| C/C++ | Conan 1 and 2 `conan.lock` | Conan 1 graph nodes and edges; Conan 2 locked reference candidates without an inferred selected graph. |
| Elixir | `mix.lock` literal map | Hex, Git, and path identities; Hex dependency aliases remain conditional until version constraints and direct roots are verified. |
| Erlang | Rebar3 `rebar.lock` v1.1/v1.2 | Hex package pins and immutable Git refs from literal Erlang terms. |
| Crystal | Shards `shard.lock` v1/v2 with optional `shard.yml` | Locked Git, Mercurial, Fossil, and local references; direct project requirements from the paired manifest. |
| Haskell | Cabal `cabal.project.freeze` / `*.project.freeze`; Stack `stack.yaml.lock` / `*.yaml.lock` | Cabal version pins and Stack completed Hackage/Git package locations. Stack snapshot contents and selected dependencies are not inferred. |
| Julia | `Manifest.toml`, `JuliaManifest.toml`, versioned `Manifest-vX.Y.toml` variants, paired project file | Manifest v1/v2 package UUIDs and versions, explicit dependency links, project roots, and conditional weak dependencies. |
| R | `renv.lock` | Snapshot package identities, declared repository/VCS/local sources, and conditional `Requirements` links when present. |
| Conda environments | Unified `conda-lock.yml` / `.conda-lock.yml` v1 | Multi-platform Conda and Pip pins, distribution URLs and hashes, with dependency constraints kept conditional. |
| Pixi | `pixi.lock` v6/v7 with optional `pixi.toml` or Pixi-enabled `pyproject.toml` | Selected Conda and PyPI packages per environment and platform, hashes, declared origins, and conditional dependency links; paired manifest direct roots. |
| Apple | CocoaPods `Podfile.lock` | Keeps subspec and target choices. |
| Dart/Flutter | `pubspec.lock` | Hosted, Git, path, and SDK sources are distinguished. |

### Installed systems and images

| Input | Current scope |
| --- | --- |
| Debian rootfs | Installed packages from `var/lib/dpkg/status`; declared `Depends` and `Pre-Depends`. |
| Alpine rootfs | APK text v2 `lib/apk/db/installed` and binary v3 `lib/apk/db/installed.adb` (plain, deflate, or zstd); installed names and supported virtual providers. |
| RPM rootfs | SQLite `rpmdb.sqlite`, NDB `Packages.db`, and Berkeley DB `Packages`; name, epoch, version, release, architecture, capability links verified where the dependency tags settle the constraint, and exact file-path requirements linked through database ownership. |
| Installed Conda in OCI | `conda-meta/<name>-<version>-<build>.json` under any environment prefix; package identity and build are checked against the filename after final layer whiteouts. Dependency constraints, package archive bytes, and distribution origin remain unverified. |
| OCI image | Registry `image:tag` / `image@sha256:...`, local Docker daemon image with `--image-source docker`, OCI layout, or OCI/Docker save tar archive, including gzip-compressed tar; final Debian, APK, or RPM database, JAR/WAR files, Go ELF build information, and Rust cargo-auditable ELF sections after layer whiteouts. Apache httpd, Bun, Deno, HAProxy, Memcached, micromamba, PHP CLI/FPM, PostgreSQL, and Redis identities are read from final ELF executables. |
| Installed Python in OCI | `.dist-info/METADATA`, directory `.egg-info/PKG-INFO`, and legacy single-file `.egg-info` records; `Requires-Dist` and legacy `requires.txt` links when identifiable; packages explicitly listed in pip's installed `_vendor/vendor.txt`; distributions with metadata inside setuptools' `_vendor` directory, linked as embedded packages; CPython versions embedded in `/usr/local/lib/libpython*.so*` ELF files. |
| Installed Composer in OCI | `composer/installed.json` below the default or a configured vendor directory, from Composer 1 and 2; recorded package names and versions, with same-registry requirement links when identifiable. A package-owned `composer.json` at a conventional `install-path` adds file evidence when its name matches. Other package files are not verified. |
| .NET runtime manifests in OCI | `*.deps.json` files; the selected runtime target's NuGet packages, project references, package hashes, and dependency links. Non-root entries with no path to a runtime asset are omitted. The manifest does not verify that each referenced assembly is present. |
| Standalone .NET assemblies in OCI | Managed DLLs absent from a valid `.deps.json` runtime asset list, when a bounded PE VERSIONINFO resource provides an internal filename, matching file description, and product version that agree with the DLL path. The file SHA-256 is recorded; a NuGet origin or dependency graph is not inferred. Localized `*.resources.dll` files are not separate packages. |
| Installed Node in OCI | Conventional `node_modules/*/package.json` records and dependency links when identifiable; Debian system modules under `/usr/share/nodejs`; pnpm virtual-store packages reached by package symlinks in the final image; versioned Yarn installations under `/opt/yarn-v*/package.json`; Node.js runtime versions embedded in `/usr/local/bin/node` ELF executables, checked against `node_version.h` when installed. |
| Installed Ruby in OCI | Generated gemspecs under conventional Ruby gem homes and `/usr/local/bundle`, including default gems. Identity comes from matching stub, literal name/version, and filename. Runtime dependency calls are linked when a numeric version requirement selects one gem in the same home, or a matching default gem when one verified CRuby runtime is present and the source home has no candidate. Linux native gem platforms are checked against the matching generated `rbconfig.rb`; activation and distribution origin remain unknown. CRuby versions are read from the exported `ruby_version` symbol in `/usr/local/lib/libruby.so.*` ELF libraries. |
| Java archives in OCI | JAR/WAR files and identifiable nested JARs, with archive hashes and embedded Maven metadata. |
| Go binaries in OCI | Embedded Go toolchain and module versions from Linux ELF files, tied to the executable's SHA-256 and image layer. The module-to-module dependency graph is not reconstructed. |
| Rust binaries in OCI | Format 1 or newer [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable/blob/master/PARSING.md) `.dep-v0` sections in Linux ELF files; the runtime crate graph and executable SHA-256, with build-only crates excluded. |
| PostgreSQL server in OCI | `/usr/local/bin/postgres` ELF files with agreeing embedded version and build strings; the server application is tied to the executable's SHA-256 and final image layer. Package-managed paths are left to the OS database. |
| Redis server in OCI | `/usr/local/bin/redis-server` ELF files with agreeing INFO and build version strings plus a server version banner template; the application is tied to the executable's SHA-256 and final image layer. Package-managed paths are left to the OS database. |
| Bun runtime in OCI | `/usr/local/bin/bun` ELF files with agreeing Linux banner and user-agent versions, tied to the executable's SHA-256 and final image layer. Large files are streamed through a temporary file. |
| Deno runtime in OCI | `/bin/deno` ELF files with agreeing release and user-agent versions and revision strings, tied to the executable's SHA-256 and final image layer. The ELF architecture must match the image. Large files are streamed through a temporary file. |
| Apache httpd in OCI | `/usr/local/apache2/bin/httpd` ELF files with agreeing full and short server versions in read-only data and the server version output template, tied to the executable's SHA-256 and final image layer. |
| HAProxy in OCI | `/usr/local/sbin/haproxy` ELF files with agreeing version and revision strings in read-only data, tied to the executable's SHA-256 and final image layer. |
| Memcached in OCI | `/usr/local/bin/memcached` ELF files with agreeing command-line, usage, and wire-protocol versions in read-only data, tied to the executable's SHA-256 and final image layer. |
| PHP CLI in OCI | `/usr/local/bin/php` ELF files with agreeing PHP 8 and Zend Engine versions and a CLI banner template, tied to the executable's SHA-256 and final image layer. |
| PHP FPM in OCI | `/usr/local/sbin/php-fpm` ELF files with agreeing PHP 8 and Zend Engine versions, FPM markers, and a version banner template. CLI and FPM executables are identified separately. |

OCI scans accept OCI and Docker schema 2 media types, verify available descriptor SHA-256 hashes and uncompressed layer DiffIDs. A multi-image layout requires `--platform os/architecture[/variant]`. Legacy Docker save archives must contain one image. Registry references select `linux` on the host architecture by default and download only that platform's image; use `--platform` to override. The selected manifest digest is recorded in Ravel JSON.
