# Development repository fixtures

Synthetic metadata records for npm, Python, Ruby, Cargo, and Maven exercise
declared source URLs, homepage candidates, monorepo directories, URL cleaning,
and repository fields distinct from download origins. Literal example
credentials are intentionally present to verify that output removes them.

Integration tests also create OCI layers and root JavaScript manifests, checking
repository propagation, final-layer removal, merging, and both standard SBOM
schemas. No fixture requires executing package code or contacting a repository.
