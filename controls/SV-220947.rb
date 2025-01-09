control 'SV-220947' do
  title 'User Account Control must automatically deny elevation requests for standard users.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized. Denying elevation requests from standard user accounts requires tasks that need elevation to be initiated by accounts with administrative privileges. This ensures correct accounts are used on the system for privileged tasks to help mitigate credential theft.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: ConsentPromptBehaviorUser

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for standard users" to "Automatically deny elevation requests".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22662r555326_chk'
  tag severity: 'medium'
  tag gid: 'V-220947'
  tag rid: 'SV-220947r1016421_rule'
  tag stig_id: 'WN10-SO-000255'
  tag gtitle: 'SRG-OS-000373-GPOS-00157'
  tag fix_id: 'F-22651r555327_fix'
  tag 'documentable'
  tag legacy: ['SV-78311', 'V-63821']
  tag cci: ['CCI-004895', 'CCI-002038', 'CCI-002038']
  tag nist: ['SC-11 b', 'IA-11', 'IA-11']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'ConsentPromptBehaviorUser' }
    its('ConsentPromptBehaviorUser') { should cmp 0 }
  end
end
