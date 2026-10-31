Name: ravel-fixture-self
Version: 1.0
Release: 1
Summary: Ravel RPM self-provider and Boolean dependency fixture
License: MIT
BuildArch: noarch
Provides: ravel-fixture-self-virtual = 1.0
Requires: ravel-fixture-self-virtual >= 1.0
Requires: (ravel-fixture-extra if ravel-fixture-trigger)
Requires: (ravel-fixture-absent if ravel-fixture-absent-trigger)
Requires: (ravel-fixture-extra or ravel-fixture-other)

%description
Small package built for Ravel's dependency constraint integration tests.

%files
