# Declared license fixtures

These small, synthetic package records are authored for Ravel's tests. They
exercise npm lockfile versions 1–3, legacy npm objects and arrays, Composer
choices, installed npm/Composer/Conda metadata, Python core metadata and wheels,
Ruby gemspecs and archives, NuGet expressions/files/URLs, APK records, Cargo
manifests, and Maven POM declarations.

The test expectations are explicit: an informal name, classifier, unresolved
LicenseRef, or file reference is never guessed into an SPDX identifier. Composer
arrays represent OR choices; independent RubyGems/npm observations have no
assumed AND/OR relation. Conflicting root declarations remain visible.

The metadata's license statements are fixture content, not licenses for Ravel.
