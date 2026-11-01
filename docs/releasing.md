# Releasing Ravel

Release tags use semantic versions. Beta releases use `vX.Y.Z-beta.N` and are marked as GitHub prereleases.

1. Confirm `LICENSE` and `NOTICE` are present, the working tree is clean, and CI has passed on the intended commit.
2. Run `go test ./... -count=1` and `go vet ./...`.
3. Run `bash scripts/build-release.sh vX.Y.Z-beta.N --check` to compile all supported targets.
4. Tag the verified commit and push the tag.
5. Run `bash scripts/build-release.sh vX.Y.Z-beta.N dist` from that clean commit. The script writes archives, dependency license files, and `SHA256SUMS` to `dist/`.
6. Create a draft GitHub prerelease with the matching notes file and upload every archive plus `SHA256SUMS`. Check the asset names and checksums before publishing.

For the first beta, the final two commands are:

```sh
bash scripts/build-release.sh v0.1.0-beta.1 dist
gh release create v0.1.0-beta.1 dist/* \
  --draft --prerelease --verify-tag \
  --title 'Ravel v0.1.0-beta.1' \
  --notes-file docs/releases/v0.1.0-beta.1.md
```

For `v0.1.0-beta.1`, the notes file is [here](releases/v0.1.0-beta.1.md). Publishing a release is a separate step from making the repository public.
