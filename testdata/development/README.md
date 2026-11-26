# Development metadata regressions

These small, original inputs cover source metadata without downloading packages
or running project code. They are parser regressions rather than a representative
sample of every supported ecosystem.

The existing npm, Python, Ruby, Cargo, and Maven samples also exercise URL
cleaning, monorepo directories, and development links distinct from distribution
origins. Example credentials verify that exports remove them. OCI tests check
installed metadata, final-layer removal, and merged standard SBOM output.

The `ruby-mixed` input reduces two patterns observed in real Faraday and JSON
gemspecs: a literal source URI beside an interpolated changelog or a homepage
reference, and an assigned `Gem::Specification.new` constructor. `ruby-reference`
covers a literal homepage referenced by source metadata, as seen in ERB, plus
the non-interpolating percent-string syntax used by ruby-saml. The fixture names,
versions, and URLs are synthetic.

`python-project` models source-labelled PEP 621 URLs such as those declared by
the Anthropic Python SDK. `python-poetry` covers legacy Poetry repository fields.
Integration tests combine these manifests with six independent lockfile or
requirements fixtures, check application ownership, and validate CycloneDX and
SPDX exports after merging the results.

Unit tests also cover computed source expressions, unsupported Ruby syntax,
dynamic Python fields, metadata precedence, documentation-only URLs, and stale
application identities. Runtime metadata evaluation and registry enrichment are
outside these tests.
