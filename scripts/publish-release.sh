#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || ! "$1" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-beta\.(0|[1-9][0-9]*))?$ ]]; then
  echo "usage: $0 vX.Y.Z[-beta.N] SOURCE_COMMIT" >&2
  exit 2
fi

release_tag="$1"
source_commit="$2"
prerelease=false
latest=true
if [[ "$release_tag" == *-beta.* ]]; then
  prerelease=true
  latest=false
fi
git fetch origin main --tags
test "$(git rev-parse HEAD)" = "$source_commit"
test "$(git rev-parse origin/main)" = "$source_commit"

if git rev-parse -q --verify "refs/tags/$release_tag^{commit}" >/dev/null; then
  test "$(git rev-parse "refs/tags/$release_tag^{commit}")" = "$source_commit"
else
  git -c user.name='github-actions[bot]' -c user.email='41898282+github-actions[bot]@users.noreply.github.com' \
    tag -a "$release_tag" -m "Ravel $release_tag" "$source_commit"
  git push origin "refs/tags/$release_tag"
fi

if ! gh release view "$release_tag" >/dev/null 2>&1; then
  release_notes=(--notes-file "docs/releases/$release_tag.md")
  if [[ ! -f "docs/releases/$release_tag.md" ]]; then
    previous_tag="$(git describe --tags --match 'v[0-9]*' --abbrev=0 "$source_commit^" 2>/dev/null || true)"
    release_notes=(--generate-notes)
    if [[ -n "$previous_tag" ]]; then
      release_notes+=(--notes-start-tag "$previous_tag")
    fi
  fi
  gh release create "$release_tag" dist/* \
    --prerelease="$prerelease" --verify-tag --fail-on-no-commits --latest="$latest" \
    --title "Ravel $release_tag" "${release_notes[@]}"
fi
if [[ "$(gh release view "$release_tag" --json isDraft --jq .isDraft)" == true ]]; then
  gh release upload "$release_tag" dist/* --clobber
  gh release view "$release_tag" --json isDraft,isPrerelease,assets > release-metadata.json
  python3 scripts/verify-release-assets.py "$release_tag" dist/SHA256SUMS release-metadata.json --allow-draft
  gh release edit "$release_tag" --draft=false --prerelease="$prerelease" --latest="$latest"
fi
gh release view "$release_tag" --json isDraft,isPrerelease,assets > release-metadata.json
python3 scripts/verify-release-assets.py "$release_tag" dist/SHA256SUMS release-metadata.json
