control 'SV-220862' do
  title 'The Windows Remote Management (WinRM) client must not use Basic authentication.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowBasic

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22577r555071_chk'
  tag severity: 'high'
  tag gid: 'V-220862'
  tag rid: 'SV-220862r958510_rule'
  tag stig_id: 'WN10-CC-000330'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-22566r555072_fix'
  tag 'documentable'
  tag legacy: ['V-63335', 'SV-77825']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client') do
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should cmp 0 }
  end
end
