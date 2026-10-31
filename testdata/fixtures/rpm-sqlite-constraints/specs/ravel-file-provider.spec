Name: ravel-fixture-file-provider
Version: 1.0
Release: 1
Summary: Ravel RPM owned-file dependency fixture
License: MIT
BuildArch: noarch

%description
Small package built for Ravel's file ownership integration tests.

%install
mkdir -p %{buildroot}/usr/share/ravel-fixture
printf 'fixture\n' > %{buildroot}/usr/share/ravel-fixture/tool
printf 'ghost\n' > %{buildroot}/usr/share/ravel-fixture/ghost

%files
/usr/share/ravel-fixture/tool
%ghost /usr/share/ravel-fixture/ghost
