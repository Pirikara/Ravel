# WordPress header fixtures

These header-only fixtures retain factual names and versions from local snapshots of WordPress/Create Block Theme, Secure Custom Fields, and Hello Dolly. They contain no upstream plugin implementation. Site Loader and Nested Test Fixture are synthetic. The latter is below the plugin entry-point depth and must be excluded. The separate wordpress-source fixture is synthetic and must never execute PHP.

The integration suite separately tests declared dependencies, ambiguous plugin slugs, missing versions, final-layer replacements, whiteouts, and symlinks.
