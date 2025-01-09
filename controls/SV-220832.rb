control 'SV-220832' do
  title 'Administrator accounts must not be enumerated during elevation.'
  desc 'Enumeration of administrator accounts when elevating can provide part of the logon information to an unauthorized user.  This setting configures the system to always require users to type in a username and password to elevate a running application.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\

Value Name: EnumerateAdministrators

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Credential User Interface >> "Enumerate administrator accounts on elevation" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22547r554981_chk'
  tag severity: 'medium'
  tag gid: 'V-220832'
  tag rid: 'SV-220832r958518_rule'
  tag stig_id: 'WN10-CC-000200'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-22536r554982_fix'
  tag 'documentable'
  tag legacy: ['V-63679', 'SV-78169']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI') do
    it { should have_property 'EnumerateAdministrators' }
    its('EnumerateAdministrators') { should cmp 0 }
  end
end
