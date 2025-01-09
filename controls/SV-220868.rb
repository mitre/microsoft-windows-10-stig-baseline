control 'SV-220868' do
  title 'The Windows Remote Management (WinRM) client must not use Digest authentication.'
  desc 'Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowDigest

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Disallow Digest authentication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22583r555089_chk'
  tag severity: 'medium'
  tag gid: 'V-220868'
  tag rid: 'SV-220868r958510_rule'
  tag stig_id: 'WN10-CC-000360'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-22572r555090_fix'
  tag 'documentable'
  tag legacy: ['V-63341', 'SV-77831']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client') do
    it { should have_property 'AllowDigest' }
    its('AllowDigest') { should cmp 0 }
  end
end
