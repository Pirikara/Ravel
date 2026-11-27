# Declared licenses

Ravel collects license declarations already present in supported package
metadata. It does not scan source files for license text or make a legal
compliance determination. Scanning does not fetch license information from
registries or execute package code.

| Input | Collected fields |
| --- | --- |
| npm | `license` and legacy `licenses` in package-lock v1–v4, installed `package.json`, and npm archives; the adjacent root manifest |
| Bun, pnpm, Yarn | The adjacent root `package.json` (also Yarn Berry workspace package manifests) |
| Composer | `license` in lockfiles and installed package records |
| Python | `License-Expression`, legacy `License`, license classifiers, and `License-File` from installed core metadata and wheels |
| RubyGems | Literal `license`/`licenses` assignments in source and installed gemspecs, and declarations in gem archive metadata |
| NuGet | `.nuspec` license expressions, license-file references, and legacy license URLs in `.nupkg` archives |
| Cargo | The root manifest's literal `license`/`license-file`; `license`/`license_file` in explicit Cargo resolver output |
| Maven | Names and URLs in the root POM's `licenses` section |
| renv and Pixi | Package `License` declarations in `renv.lock`; selected package `license` declarations in `pixi.lock`, including source selections |
| Installed systems | APK v2/v3 license fields, RPM database/archive license tags, Conda `license`, and R DESCRIPTION `License` |

A format that does not record a license cannot supply one. For example,
`Gemfile.lock`, `go.sum`, and a Python requirements file do not declare each
dependency's license. A project license is never assigned to its dependencies.
Inherited Cargo workspace declarations require resolver output to obtain the
effective value. Dynamic Ruby assignments remain unresolved and appear in
coverage.

## Output

Native JSON includes `licenses` on components and the root identity. Each entry
retains a `kind`, the declared `value`, and source `evidence`. Recognized SPDX
expressions also include a canonical `expression`; unrecognized names and
unresolved custom LicenseRefs retain their original text. URL credentials and
query secrets are removed. Identifier recognition uses the embedded SPDX
license/exception list version 3.29.0, without a scan-time network request.

CycloneDX 1.7 includes standard `licenses` entries acknowledged as `declared`.
Named declarations remain names, longer notices remain attached text, and
license URLs become `license` external references. File references and
classifiers remain metadata, without being promoted to license identifiers.
Every original declaration and its evidence is also retained in the
`ravel:licenseDeclaration` property.

SPDX 2.3 uses `licenseDeclared` when the declarations establish one recognized
expression. Otherwise it uses `NOASSERTION`, with the original declarations and
evidence in `licenseComments`. `licenseConcluded` remains `NOASSERTION`.

Multiple declarations are not automatically joined with AND or OR. Composer
explicitly defines its license array as alternatives, so Ravel can produce an
OR expression. RubyGems and legacy npm arrays do not establish that relation;
distinct values remain independent observations. Contradictory root manifest
and lockfile declarations are retained and leave SPDX `licenseDeclared`
unresolved.

For image scans, installed metadata is preferred. When it has no declarations,
an unambiguous matching lockfile can supply declared metadata, with evidence
marked `image-lockfile-correlation`. This does not establish a license
conclusion for the installed bytes. Ambiguous lockfile matches remain unresolved.

License changes participate in `ravel diff`; changes only to source paths,
digests, or declaration order do not count as a license change.

Format semantics are documented by [Composer](https://getcomposer.org/doc/04-schema.md#license),
[RubyGems](https://guides.rubygems.org/specification-reference/#licenses),
[npm](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#license),
[Python](https://packaging.python.org/en/latest/specifications/core-metadata/),
and [NuGet](https://learn.microsoft.com/nuget/reference/nuspec).
