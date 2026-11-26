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
| Ruby source/installed gemspecs | Literal `metadata["source_code_uri"]` assignments or literal metadata hashes; repository-shaped literal `homepage` fallback |
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

Ruby code is not evaluated. Computed metadata values remain unresolved. Static
Cargo workspace inheritance and inherited Maven parent SCM values are not
resolved by these manifest readers. Inputs that contain no repository metadata
cannot supply it; a registry lookup is not performed to fill the gap.

All links describe declarations or candidates. They do not certify that the
repository is authoritative, that the installed bytes came from it, or that a
particular commit corresponds to the package release. Adding a development
repository never changes the package's distribution origin or source-qualified
PURL.

See the metadata definitions for [npm](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#repository),
[Python](https://packaging.python.org/en/latest/specifications/well-known-project-urls/),
and [RubyGems](https://guides.rubygems.org/specification-reference/#metadata).
