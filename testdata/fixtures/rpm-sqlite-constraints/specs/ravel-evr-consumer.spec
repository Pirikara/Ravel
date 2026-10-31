Name: ravel-fixture-evr-consumer
Version: 1.0
Release: 1
Summary: Ravel RPM version requirement fixture
License: MIT
BuildArch: noarch
Requires: ravel-fixture-evr-gt > 1.0
Requires: ravel-fixture-evr-lt < 1.0.1
Requires: ravel-fixture-evr-release < 1.0^git1-2
Requires: ravel-fixture-evr-no-release = 1.0^git1
Requires: ravel-fixture-evr-pre > 1.0~beta1
Requires: ravel-fixture-evr-separator = 1.0
Requires: ravel-fixture-evr-bad >= 1.0.1
Requires: ravel-fixture-evr-release-bad >= 1.0^git1-2

%description
Satisfying and unsatisfying RPM version constraints for Ravel tests.

%files
