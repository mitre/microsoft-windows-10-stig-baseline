control 'SV-220825' do
  title 'The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.'
  desc 'Control of credentials and the system must be maintained within the enterprise.  Enabling this setting allows enterprise credentials to be used with modern style apps that support this, instead of Microsoft accounts.'
  desc 'check', 'Windows 10 LTSC\\B versions do not support the Microsoft Store and modern apps; this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: MSAOptional

Value Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Runtime >> "Allow Microsoft accounts to be optional" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22540r554960_chk'
  tag severity: 'low'
  tag gid: 'V-220825'
  tag rid: 'SV-220825r991589_rule'
  tag stig_id: 'WN10-CC-000170'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22529r554961_fix'
  tag 'documentable'
  tag legacy: ['V-63659', 'SV-78149']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'MSAOptional' }
    its('MSAOptional') { should cmp 1 }
  end
end
