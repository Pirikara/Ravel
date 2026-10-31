# RPM dependency constraint fixture

The original specs in `specs/` define a versioned requirement that is not
satisfied by `ravel-fixture-base` (`>= 2.0` versus `= 1.0`) and an unversioned
requirement that is satisfied. The base spec is in
`../rpm-sqlite-basic/specs/ravel-base.spec`.

The third spec requires a capability it provides itself and includes three RPM
Boolean dependencies. Its active `if` and both `if else` branches link to the
EVR provider; the inactive `if` condition adds no edge; and the `or` expression
remains explicitly unparsed. The self-provided requirement needs no
inter-package edge.

The file provider owns a regular file and a `%ghost` record. The file consumer
requires both paths and a nonexistent path. Ravel links only the regular file
by exact database ownership; the ghost and absent paths remain unresolved.

The EVR provider declares capabilities with caret, tilde, release, and segment
separator forms. The consumer exercises six satisfied and two unsatisfied RPM
version constraints, including a requirement that omits the release.

The RPMs were built with `rpmbuild` on Fedora 42, then installed with
`rpm --justdb --nodeps` into an isolated SQLite RPM database. The `--nodeps`
flag intentionally preserves the unsatisfied requirement for the test.
No operating system package database was copied into this fixture.
