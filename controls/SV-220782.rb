control 'SV-220782' do
  title 'Windows 10 permissions for the Application event log must prevent access by non-privileged accounts.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are necessary to provide a trail of evidence in case the system or network is compromised.  The Application event log may be  susceptible to tampering if proper permissions are not applied.'
  desc 'check', 'Verify the permissions on the Application event log (Application.evtx). Standard user accounts or groups must not have access. The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory. They may have been moved to another folder.

If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.

NOTE: If "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES" has Special Permissions, this would not be a finding.'
  desc 'fix', 'Ensure the permissions on the Application event log (Application.evtx) are configured to prevent standard user accounts or groups from having access. The default permissions listed below satisfy this requirement.

Eventlog - Full Control
SYSTEM - Full Control
Administrators - Full Control

The default location is the "%SystemRoot%\\SYSTEM32\\WINEVT\\LOGS" directory.

If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as "NT Service\\Eventlog".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22497r554831_chk'
  tag severity: 'medium'
  tag gid: 'V-220782'
  tag rid: 'SV-220782r958434_rule'
  tag stig_id: 'WN10-AU-000515'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-22486r554832_fix'
  tag 'documentable'
  tag legacy: ['V-63533', 'SV-78023']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']

  get_system_root = command('Get-ChildItem Env: | Findstr SystemRoot').stdout.strip
  system_root = get_system_root[11..get_system_root.length]
  systemroot = system_root.strip

  describe file("#{systemroot}\\SYSTEM32\\WINEVT\\LOGS\\Application.evtx") do
    it { should be_allowed('full-control', by_user: 'NT SERVICE\\EventLog') }
    it { should be_allowed('full-control', by_user: 'NT AUTHORITY\\SYSTEM') }
    it { should be_allowed('full-control', by_user: 'BUILTIN\\Administrators') }
  end
end
