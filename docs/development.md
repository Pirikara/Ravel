# Development

```sh
go test ./... -count=1
go vet ./...
```

The fixture tree covers supported inputs as well as intentionally unsupported and malformed cases. Java archive fixtures are scanned as JAR/WAR files, including cases that must be rejected. The integration suite validates CycloneDX 1.7 and SPDX 2.3 against their JSON Schemas and checks package counts, dependency edges, provenance, URL redaction, conditional relationships, and coverage. Fixtures include generated npm, pnpm, Yarn, Bundler, Composer, Bun, Deno, uv, and dotnet lockfiles; WordPress plugin headers; Debian, APK (including a converted v3 database from an Alpine image), and RPM installed databases; package archives; and OCI images with a Linux Go executable built for the test.

The integration suite also checks source-backed package, graph, and unknown-origin assertions over 50 representative cases across 34 managers. These cover lockfile ecosystems in the [supported-input table](supported-inputs.md), including npm v1–v4, pnpm v6/v9, Yarn Classic/Berry, Bun text locks v0–v2, Deno v3–v5, and Swift resolved files v1–v3. Dedicated WordPress tests cover source and installed layouts, header bounds, missing versions, and final-layer changes. Scanner output can reveal claims to investigate, while the fixture files determine the expected result.

The real Maven resolver tests are opt-in:

```sh
RAVEL_TEST_REAL_MAVEN=1 go test ./integration \
  -run 'TestMavenResolverWithReal(Reactor|Maven)' -count=1
```

Registry enrichment tests use local TLS servers and saved version responses. New collectors should include representative real-format fixtures and assertions about identity, graph, origin, and output loss.

The [ground-truth checks](groundtruth-benchmark.md) use external package-manager records and selected fixed BBP snapshots to measure name/version and declared-origin agreement within a stated scan scope.

See [third-party notices](../THIRD_PARTY_NOTICES.md) for licenses of the bundled RPM database reader and zstd decoder.
