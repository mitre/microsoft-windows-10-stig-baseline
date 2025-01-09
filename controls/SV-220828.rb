control 'SV-220828' do
  title 'The default autorun behavior must be configured to prevent autorun commands.'
  desc 'Allowing autorun commands to execute may introduce malicious code to a system.  Configuring this setting prevents autorun commands from executing.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

Value Name: NoAutorun

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22543r554969_chk'
  tag severity: 'high'
  tag gid: 'V-220828'
  tag rid: 'SV-220828r958804_rule'
  tag stig_id: 'WN10-CC-000185'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-22532r554970_fix'
  tag 'documentable'
  tag legacy: ['V-63671', 'SV-78161']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    it { should have_property 'NoAutorun' }
    its('NoAutorun') { should cmp 1 }
  end
end
