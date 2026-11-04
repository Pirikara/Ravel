#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 TAG SOURCE_COMMIT" >&2
  exit 2
fi

release_tag="$1"
source_commit="$2"
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
  previous_tag="$(git tag --list 'v*-beta.*' --sort=-version:refname | grep -Fxv "$release_tag" | head -1 || true)"
  notes_start=()
  if [[ -n "$previous_tag" ]]; then
    notes_start=(--notes-start-tag "$previous_tag")
  fi
  gh release create "$release_tag" dist/* \
    --prerelease --verify-tag --generate-notes --fail-on-no-commits --latest=false \
    --title "Ravel $release_tag" "${notes_start[@]}"
fi
if [[ "$(gh release view "$release_tag" --json isDraft --jq .isDraft)" == true ]]; then
  gh release upload "$release_tag" dist/* --clobber
  gh release view "$release_tag" --json isDraft,isPrerelease,assets > release-metadata.json
  python3 scripts/verify-release-assets.py "$release_tag" dist/SHA256SUMS release-metadata.json --allow-draft
  gh release edit "$release_tag" --draft=false --prerelease
fi
gh release view "$release_tag" --json isDraft,isPrerelease,assets > release-metadata.json
python3 scripts/verify-release-assets.py "$release_tag" dist/SHA256SUMS release-metadata.json
