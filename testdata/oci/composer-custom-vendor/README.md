# Composer custom vendor directory sample

`dependencies/composer/installed.json` was generated with Composer 2.10.2.
The local project is based on `../../fixtures/composer-generated-2`, with
`config.vendor-dir` set to `dependencies`. Running
`composer install --no-scripts --no-plugins --no-interaction` produced the
manifest without contacting a package repository.

The OCI integration test reads this generated manifest and the matching
`composer.json` to check that the installed packages are detected outside the
default `vendor` directory.
