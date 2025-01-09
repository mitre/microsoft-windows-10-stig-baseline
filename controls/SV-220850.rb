control 'SV-220850' do
  title 'Remote Desktop Services must always prompt a client for passwords upon connection.'
  desc 'This setting controls the ability of users to supply passwords automatically as part of their remote desktop connection. Disabling this setting would allow anyone to use the stored credentials in a connection item to connect to the terminal server.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: fPromptForPassword

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Always prompt for password upon connection" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22565r555035_chk'
  tag severity: 'medium'
  tag gid: 'V-220850'
  tag rid: 'SV-220850r1016415_rule'
  tag stig_id: 'WN10-CC-000280'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-22554r555036_fix'
  tag 'documentable'
  tag legacy: ['SV-78223', 'V-63733']
  tag cci: ['CCI-004895', 'CCI-002038', 'CCI-002038']
  tag nist: ['SC-11 b', 'IA-11', 'IA-11']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'fPromptForPassword' }
    its('fPromptForPassword') { should cmp 1 }
  end
end
