# Releasing Ravel

Beta releases use `vX.Y.Z-beta.N` tags and are published as GitHub prereleases. The [Release workflow](../.github/workflows/release.yml) handles the full release from one manual run.

1. Merge the changes to `main` and confirm its CI succeeds.
2. In GitHub Actions, open **Release**, select **Run workflow** on `main`, and enter the new tag (for example `v0.1.0-beta.4`). Alternatively, run `gh workflow run release.yml --ref main -f tag=v0.1.0-beta.4`.
3. Watch the single workflow. It tests and cross-builds five archives, verifies checksums, creates the tag and published GitHub prerelease with generated notes, publishes the Linux amd64/arm64 container to GHCR, and updates the Homebrew tap formula. It also checks that the container is publicly pullable.

The workflow rejects an existing tag pointing to another commit and stops if `main` advances during verification. Rerunning the same tag is supported after a later publish step fails: the existing release assets must match the verified build. No release preparation commit or manual draft publication is needed. README and installation examples use a tag selected from [GitHub Releases](https://github.com/Pirikara/Ravel/releases), so they do not require a version edit for each beta.

The tap update uses the `HOMEBREW_TAP_DEPLOY_KEY` Actions secret, a write-enabled deploy key scoped only to [`Pirikara/homebrew-tap`](https://github.com/Pirikara/homebrew-tap). If the secret is missing or the key is invalid, the workflow stops before publishing. The `GITHUB_TOKEN` writes the release tag and GitHub Release only in Ravel and pushes the GHCR image.
