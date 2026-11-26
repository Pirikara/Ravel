# Declared license metadata

This package recognizes SPDX expressions in package metadata. It does not detect
licenses from file contents or conclude which terms apply to installed bytes.
Unrecognized declarations, file references, and classifiers retain their values.
License URLs use Ravel's URL cleaning policy.

`spdx.json` contains only identifiers from the official SPDX License List 3.29.0:

- https://github.com/spdx/license-list-data/blob/v3.29.0/json/licenses.json
- https://github.com/spdx/license-list-data/blob/v3.29.0/json/exceptions.json

The lists are embedded for offline use. Identifier/operator spelling is
canonicalized; informal aliases and unresolved `LicenseRef` declarations are not
mapped to known licenses. Deprecated SPDX identifiers are retained as listed.

Composer license arrays explicitly represent alternatives. RubyGems and legacy
npm license arrays do not establish a combined SPDX expression. Multiple
independent statements are retained without inventing an AND/OR relationship.
