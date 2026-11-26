# Development repositories

Ravel records upstream development repository candidates separately from package
registries, distribution URLs, and VCS installation sources. A repository link
does not establish which artifact was downloaded or which revision built it.
Collection uses the supplied metadata without contacting those repositories.

| Input | Repository information |
| --- | --- |
| npm installed packages and archives | `package.json` `repository`, as a string or object; object `directory` for a monorepo subdirectory |
| npm, Bun, pnpm, Yarn projects | The adjacent named root application's `package.json`; Yarn Berry workspace package manifests |
| Python installed distributions, setuptools bundled metadata, and wheels | Source-labelled `Project-URL` entries; repository-shaped `Homepage` / legacy `Home-page` fallback |
| Python projects scanned through uv, Poetry, PDM, pylock, Pipenv, or requirements | Adjacent `pyproject.toml`: source-labelled `project.urls`, or legacy `tool.poetry.repository`; repository-shaped homepage fallback |
| Ruby source/installed gemspecs | Literal `metadata["source_code_uri"]` assignments or metadata hash entries; a direct reference to a uniquely declared literal `homepage`; repository-shaped literal `homepage` fallback |
| Ruby gem archives | `metadata.source_code_uri`; repository-shaped `homepage` fallback |
| Cargo | Literal root `package.repository`; root and dependency `repository` values from explicit Cargo resolver output |
| Maven | The root POM's `scm.url`, `scm.connection`, and `scm.developerConnection` |
| Installed R packages | Repository-shaped links in the DESCRIPTION `URL` field |
| Existing VCS metadata | VCS origin records also supply development candidates, including Composer and supported lockfile Git sources |

npm repository strings support full URLs, SCP-style Git URLs, and explicit
GitHub, GitLab, Bitbucket, or gist shorthand. Bare `owner/repo` follows npm's
GitHub shorthand convention. Package names alone never supply a repository.
Credentials and URL query parameters are removed before storage.

Python source labels follow the well-known `source`, `repository`, `sourcecode`,
and `github` labels, with case, ASCII punctuation, and whitespace normalized.
Documentation and issue-tracker labels are not source declarations.

Python project metadata belongs to the application, not its installed or locked
dependencies. uv metadata is attached to its existing application component;
other manifest readers retain the named root identity. A mismatched uv application
name or static version is reported instead of attaching the URL to another
identity. PEP 621 metadata takes precedence over legacy Poetry fields. Dynamic
URL and version fields are not evaluated.

Ruby readers accept ordinary quoted strings and bounded non-interpolating `%q`
strings. An unrelated computed value in a metadata hash does not discard a
literal source URL. Computed source URLs remain unresolved, and a source URL
referencing `spec.homepage` is declared only when that homepage has one literal
assignment. Source gemspec constructors may be assigned to a local variable.

When no usable explicit source is available, Python and Ruby can retain a
homepage as a candidate if it has the two-segment repository shape of GitHub,
GitLab, Bitbucket, or Codeberg. R uses the same conservative shape check for its
project URLs. Other project websites and issue-tracker paths are not relabelled
as code repositories. These candidates remain inferred.

## Output and evidence

Native JSON uses the `development` array. Each record has a component occurrence,
`safeUrl`, `status`, optional `directory`, and input evidence. Statuses distinguish
explicit `declared` metadata, `inferred_from_homepage`,
`inferred_from_project_url`, `inferred_from_vcs_source`, and image correlations.

CycloneDX includes standard `vcs` external references and retains the complete
record in `ravel:developmentRepositoryEvidence`, alongside the existing
`ravel:developmentRepository` URL property. SPDX 2.3 retains the record as JSON
in the package `comment`. Root application declarations are exported on the root
application too, and remain scoped when multiple scans are merged.

The repository's monorepo directory participates in `ravel diff`. Source path,
digest, or evidence-only changes do not change the repository's semantic identity.

## Limits

Ruby code is not evaluated. Computed metadata values and unsupported Ruby syntax
remain unresolved. Python build hooks and dynamic metadata are not executed. Static
Cargo workspace inheritance and inherited Maven parent SCM values are not
resolved by these manifest readers. These static readers do not query registries
for missing URLs. The separate `ravel enrich` command can obtain supported
registry metadata; PyPI enrichment requires a declared index and a matching
release artifact SHA-256 before attaching project-supplied source metadata.

All links describe declarations or candidates. They do not certify that the
repository is authoritative, that the installed bytes came from it, or that a
particular commit corresponds to the package release. Adding a development
repository never changes the package's distribution origin or source-qualified
PURL.

See the metadata definitions for [npm](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#repository),
[Python](https://packaging.python.org/en/latest/specifications/well-known-project-urls/),
and [RubyGems](https://guides.rubygems.org/specification-reference/#metadata).
