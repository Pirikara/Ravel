# Development

```sh
go test ./... -count=1
go vet ./...
```

The fixture tree has 267 directories. A default CLI sweep succeeds on 232; 21 deliberately unsupported or malformed cases fail. The other 14 directories contain Java archives that are scanned as JAR/WAR files: 10 valid archives succeed, and 4 invalid or unsafe archives fail. The integration suite validates CycloneDX 1.7 and SPDX 2.3 against their JSON Schemas and checks package counts, dependency edges, provenance, URL redaction, conditional relationships, and coverage. Fixtures include generated npm, pnpm, Yarn, Bundler, Composer, Bun, Deno, uv, and dotnet lockfiles; Debian, APK (including a converted v3 database from an Alpine image), and RPM installed databases; package archives; and OCI images with a Linux Go executable built for the test.

The integration suite also checks source-backed package, graph, and unknown-origin assertions over 50 representative cases across 34 managers. These cover every ecosystem in the [supported-input table](supported-inputs.md), including npm v1–v4, pnpm v6/v9, Yarn Classic/Berry, Bun text locks v0–v2, Deno v3–v5, and Swift resolved files v1–v3. Scanner output can reveal claims to investigate, while the fixture files determine the expected result.

The real Maven resolver tests are opt-in:

```sh
RAVEL_TEST_REAL_MAVEN=1 go test ./integration \
  -run 'TestMavenResolverWithReal(Reactor|Maven)' -count=1
```

Registry enrichment tests use local TLS servers and saved version responses. New collectors should include representative real-format fixtures and assertions about identity, graph, origin, and output loss.

The [ground-truth checks](groundtruth-benchmark.md) use external package-manager records and selected fixed BBP snapshots to measure name/version and declared-origin agreement within a stated scan scope.

See [third-party notices](../THIRD_PARTY_NOTICES.md) for licenses of the bundled RPM database reader and zstd decoder.
