# RPM NDB dependency constraint fixture

This is the NDB version of `../rpm-sqlite-constraints`. Its packages were
built from the public spec files in that fixture, installed into an isolated
SQLite database, and converted to NDB with Fedora 42 `rpmdb --rebuilddb` and
`_db_backend ndb`.

It covers exact file ownership, a `%ghost` record, an absent file requirement,
capability version constraints, a self-provided capability, and an RPM Boolean
dependency. No operating system package database was copied into this fixture.
