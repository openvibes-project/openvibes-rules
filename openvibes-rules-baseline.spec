Name:           openvibes-rules-baseline
Version:        %{rule_version}
Release:        1%{?dist}
Summary:        OpenVIBES signed baseline rule set
License:        MIT
URL:            https://github.com/openvibes-project/openvibes-rules
BuildArch:      noarch
Source0:        baseline.json
Source1:        baseline.key
# The threat-alarm rule set (P14), from alarms/ (build-rpm.sh defines it).
Source2:        %{alarms_dir}/alarms.json
Source3:        %{alarms_dir}/alarms.key

%description
The OpenVIBES project's signed baseline rule set, the threat-alarm rule
set (baseline-alarms, for agents 0.2 and later), and their public keys.
openvibes-admin Setup trusts the keys and publishes the rule sets.

%prep

%build

%install
install -D -m 0644 %{SOURCE0} %{buildroot}%{_datadir}/openvibes/rules/baseline.json
install -D -m 0644 %{SOURCE1} %{buildroot}%{_datadir}/openvibes/rules/baseline.key
install -D -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/openvibes/rules/alarms.json
install -D -m 0644 %{SOURCE3} %{buildroot}%{_datadir}/openvibes/rules/alarms.key

%files
%dir %{_datadir}/openvibes
%dir %{_datadir}/openvibes/rules
%{_datadir}/openvibes/rules/baseline.json
%{_datadir}/openvibes/rules/baseline.key
%{_datadir}/openvibes/rules/alarms.json
%{_datadir}/openvibes/rules/alarms.key

%changelog
* Mon Sep 28 2026 itismelime <26064407+itismelime@users.noreply.github.com> - %{rule_version}-1
- Baseline rule set version %{rule_version}; the rules' own history is the
  openvibes-rules git log and its GitHub releases.
