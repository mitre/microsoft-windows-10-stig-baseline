control 'SV-220857' do
  title 'The Windows Installer Always install with elevated privileges must be disabled.'
  desc 'Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: AlwaysInstallElevated

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Always install with elevated privileges" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22572r555056_chk'
  tag severity: 'high'
  tag gid: 'V-220857'
  tag rid: 'SV-220857r1016417_rule'
  tag stig_id: 'WN10-CC-000315'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-22561r555057_fix'
  tag 'documentable'
  tag legacy: ['V-63325', 'SV-77815']
  tag cci: ['CCI-003980', 'CCI-001812', 'CCI-001812']
  tag nist: ['CM-11 (2)', 'CM-11 (2)', 'CM-11 (2)']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
    it { should have_property 'AlwaysInstallElevated' }
    its('AlwaysInstallElevated') { should cmp 0 }
  end
end
