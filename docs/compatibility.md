# Compatibility policy

This policy applies to stable releases starting with v0.1.0. The [supported input matrix](supported-inputs.md) and [known limits](limitations.md) define the scan's scope. A stable release does not certify complete detection in every repository or image.

## Versioning

Ravel uses `vMAJOR.MINOR.PATCH` for stable releases and `vMAJOR.MINOR.PATCH-beta.N` for prereleases. During 0.x development, incompatible CLI or output changes require a new minor release with migration notes. Patch releases preserve documented command behavior and existing JSON field meanings. New commands, optional flags, optional fields, and detections may be added compatibly. Beta builds may change before their stable release.

## CLI and exit codes

Within a stable minor series, documented commands, flags, default output format, and exit-code meanings remain compatible. Diagnostics, progress messages, help text, human-readable reports, and HTML presentation may change; use JSON for machine processing.

| Code | Meaning |
| --- | --- |
| `0` | The command completed successfully. This alone does not establish complete scan coverage. |
| `1` | An input, scan, update, or other operation failed. |
| `2` | Invalid command usage. |
| `3` | `scan`, `merge`, or `enrich` completed with coverage issues under `--strict`; requested output was written. |

`diff` returns `0` when the comparison succeeds, including when differences exist. An available update also returns `0` with `update --check`. Neither command's exit status is a change detector.

## JSON and SBOM formats

The native `ravel-json` format has a separate `schemaVersion`, currently `"0.1"`; this is not the CLI release version. Field removal, type changes, and incompatible reinterpretation require a new schema version and a release with migration notes. Readers must reject unsupported schema versions. Ravel's native-input commands currently accept `"0.1"`.

Consumers should ignore unknown optional fields, handle new coverage codes and record values without treating them as verified claims, and accept omitted optional collections or `null`/empty collections as appropriate. Object key order and array ordering are not part of the interface. IDs are opaque relationship keys: join records using the emitted IDs rather than decoding or constructing them.

Patch releases may correct package identities, PURLs, dependency relationships, evidence, and coverage, or detect previously missed metadata. Such corrections can change counts and IDs even for unchanged input bytes. IDs also depend on scan scope and package context; they are not permanent cross-version identifiers. Preserve the CLI version, input revision or digest, options, and native output when maintaining a baseline.

The default remains CycloneDX JSON within the stable minor series. Changes to the emitted CycloneDX or SPDX specification version require a new minor release and release notes. Additional records and Ravel annotations may be added while retaining conformance to the selected format. Keep native JSON and a `--report` file when downstream consumers need the evidence or coverage omitted by a standard SBOM format.

## Update channels

Stable installations follow stable releases by default. Beta installations follow a channel that includes both beta and stable releases; the stable release of the same version supersedes its betas. `ravel update --channel stable` explicitly selects stable releases.

Homebrew's normal formula follows stable releases after the first stable release is published. Later beta releases remain available as versioned GitHub downloads and GHCR images. Pin a release tag in automation and review release notes before changing a minor version.
