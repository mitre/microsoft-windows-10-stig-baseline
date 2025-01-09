control 'SV-220848' do
  title 'Passwords must not be saved in the Remote Desktop Client.'
  desc 'Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system. The system must be configured to prevent users from saving passwords in the Remote Desktop Client.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: DisablePasswordSaving

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Connection Client >> "Do not allow passwords to be saved" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22563r555029_chk'
  tag severity: 'medium'
  tag gid: 'V-220848'
  tag rid: 'SV-220848r1016414_rule'
  tag stig_id: 'WN10-CC-000270'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-22552r555030_fix'
  tag 'documentable'
  tag legacy: ['V-63729', 'SV-78219']
  tag cci: ['CCI-004895', 'CCI-002038', 'CCI-002038']
  tag nist: ['SC-11 b', 'IA-11', 'IA-11']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'DisablePasswordSaving' }
    its('DisablePasswordSaving') { should cmp 1 }
  end
end
