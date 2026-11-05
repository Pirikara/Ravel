# DeepBits SBOM benchmark fixtures

These files are copied from [DeepBitsTechnology/sbom-benchmark](https://github.com/DeepBitsTechnology/sbom-benchmark) at commit `e6bcf23b2f4e384f9fc398793529583845612b63` under the MIT license in [LICENSE](LICENSE).

| Local fixture | Upstream file | Reference used by the integration test |
| --- | --- | --- |
| `composer/composer.lock` | `php/composerlock/composer.lock` | Package identities and dependency declarations |
| `composer/install.txt` | `php/composerlock/groundtruth` | Composer install log; 47 installed name/version pairs |
| `npm/package.json` | `javascript/packagejson/package.json` | Root manifest for lockfile context |
| `npm/package-lock.json` | `javascript/packagejson/groundtruth` | npm's resolved package and tarball records |
| `cargo/Cargo.toml` | `rust/cargo/Cargo.toml` | Root manifest for lockfile context |
| `cargo/Cargo.lock` | `rust/cargolock/Cargo.lock` | Cargo's resolved package records |

`integration/groundtruth_test.go` compares Ravel's output to these package-manager records. The Composer install log is separate evidence of an install. For npm and Cargo, the lockfile itself is the reference; those cases test faithful parsing of declared resolved packages, not whether every package was present in a built artifact. The npm case checks official-registry tarball URLs. The Composer case also checks the dependency edges and declared source URLs in the lockfile.
