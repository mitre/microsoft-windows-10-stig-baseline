control 'SV-220945' do
  title 'User Account Control must, at minimum, prompt administrators for consent on the secure desktop.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures the elevation requirements for logged on administrators to complete a task that requires raised privileges.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorAdmin

Value Type: REG_DWORD
Value: 2 (Prompt for consent on the secure desktop)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode" to "Prompt for consent on the secure desktop".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22660r555320_chk'
  tag severity: 'medium'
  tag gid: 'V-220945'
  tag rid: 'SV-220945r958518_rule'
  tag stig_id: 'WN10-SO-000250'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-22649r555321_fix'
  tag 'documentable'
  tag legacy: ['V-63819', 'SV-78309']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'ConsentPromptBehaviorAdmin' }
    its('ConsentPromptBehaviorAdmin') { should cmp 2 }
  end
end
