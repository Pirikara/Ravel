# Ground-truth checks

Ravel has two complementary checks for package detection accuracy:

1. The checked-in [DeepBits fixtures](../testdata/groundtruth/deepbits/README.md) run in the integration suite. They compare package name/version multisets, 101 Composer dependency edges, and declared origins where the reference provides them.
2. `scripts/groundtruth_bbp.py` checks five fixed, local BBP snapshots against their package-manager lock records: npm, Cargo, Composer, NuGet, and SwiftPM. The snapshots and generated results stay under the ignored `comparison/` directory.

Run the checked-in cases with `go test ./integration -run TestDeepBitsGroundtruth -count=1 -v`. To repeat the local BBP check, build the current binary and run:

```sh
go build -o /tmp/ravel-groundtruth ./cmd/ravel
python3 scripts/groundtruth_bbp.py --ravel /tmp/ravel-groundtruth > comparison/bbp-audit/groundtruth-results.json
```

Python 3.11 or newer is required for the BBP script. Its source of truth is each snapshot's lockfile. The script counts repeated package placements separately, excludes the root project from external package counts, and compares NuGet IDs without case. It checks origin URLs only where the lock records them. NuGet's `packages.lock.json` has no registry URL to verify. All URLs from a lockfile are **declared**, not evidence of a completed download.

The checks answer a narrow question: whether Ravel faithfully emits the package identities, selected edges, and source claims supported by these inputs. They do not measure recall for a complete repository or built image, validate license data, or prove that a declared dependency was installed. A broader precision/recall estimate needs independently observed install or build inventories and annotated negative cases for each input scope. Counts from Syft or Trivy are useful discrepancy leads, but are not ground truth.
