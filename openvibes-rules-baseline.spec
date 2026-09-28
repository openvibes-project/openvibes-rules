Name:           openvibes-rules-baseline
Version:        %{rule_version}
Release:        1%{?dist}
Summary:        OpenVIBES signed baseline rule set
License:        MIT
URL:            https://github.com/openvibes-project/openvibes-rules
BuildArch:      noarch
Source0:        baseline.json
Source1:        baseline.key

%description
The OpenVIBES project's signed baseline rule set and its public key.
openvibes-admin Setup trusts the key and publishes the rule set.

%prep

%build

%install
install -D -m 0644 %{SOURCE0} %{buildroot}%{_datadir}/openvibes/rules/baseline.json
install -D -m 0644 %{SOURCE1} %{buildroot}%{_datadir}/openvibes/rules/baseline.key

%files
%dir %{_datadir}/openvibes
%dir %{_datadir}/openvibes/rules
%{_datadir}/openvibes/rules/baseline.json
%{_datadir}/openvibes/rules/baseline.key

%changelog
* Mon Sep 28 2026 itismelime <26064407+itismelime@users.noreply.github.com> - %{rule_version}-1
- Baseline rule set version %{rule_version}; the rules' own history is the
  openvibes-rules git log and its GitHub releases.
