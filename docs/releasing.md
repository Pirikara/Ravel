# Releasing Ravel

Release tags use semantic versions. Beta releases use `vX.Y.Z-beta.N` and are marked as GitHub prereleases.

1. Confirm `LICENSE` and `NOTICE` are present, the working tree is clean, and CI has passed on the intended commit.
2. Run `go test ./... -count=1` and `go vet ./...`.
3. Run `bash scripts/build-release.sh vX.Y.Z-beta.N --check` to compile all supported targets.
4. Add `docs/releases/vX.Y.Z-beta.N.md` with release notes and commit it before tagging.
5. Tag the verified commit and push the tag. The [release workflow](../.github/workflows/release.yml) reruns tests, builds the five archives and dependency licenses, verifies checksums, and creates a draft GitHub prerelease. It leaves publication to a maintainer.
6. Check the draft's notes, asset names, and checksums before publishing.

Run the workflow manually with an existing tag to verify its build without changing the release. The `v0.1.0-beta.1` notes file is [here](releases/v0.1.0-beta.1.md). Publishing a release is a separate step from making the repository public.
