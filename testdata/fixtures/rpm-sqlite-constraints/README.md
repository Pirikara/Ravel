# RPM dependency constraint fixture

The original specs in `specs/` define a versioned requirement that is not
satisfied by `ravel-fixture-base` (`>= 2.0` versus `= 1.0`) and an unversioned
requirement that is satisfied. The base spec is in
`../rpm-sqlite-basic/specs/ravel-base.spec`.

The RPMs were built with `rpmbuild` on Fedora 42, then installed with
`rpm --justdb --nodeps` into an isolated SQLite RPM database. The `--nodeps`
flag intentionally preserves the unsatisfied requirement for the test.
No operating system package database was copied into this fixture.
