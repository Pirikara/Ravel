# Contributing to Ravel

Thanks for helping make Ravel's SBOM claims more useful and more trustworthy.

## Report an issue

For a scan error, include the Ravel command, the input format and version, the expected result, the actual result, and the relevant coverage report. A small, redacted fixture makes a report much easier to reproduce. Remove credentials, private registry tokens, and proprietary package data before sharing files or command output.

For a feature request, describe the input or workflow and the evidence Ravel could use to support the new claim. See [supported inputs](docs/supported-inputs.md) and [known limits](docs/limitations.md) first.

## Make a change

Ravel requires Go 1.27 or newer. Build and run the test suite with:

```sh
go build ./cmd/ravel
go test ./... -count=1
go vet ./...
```

Keep identity, dependency, origin, and coverage claims tied to source evidence. If an input cannot establish a fact, preserve that uncertainty instead of filling it in from convention. New collectors and parser changes should include representative real-format fixtures and assertions for both supported and ambiguous cases. The [development guide](docs/development.md) describes the integration suite.

Open a pull request with a short explanation of the behavior, the evidence used, and the tests you ran. CI runs the full Go test suite and `go vet` on pull requests.
