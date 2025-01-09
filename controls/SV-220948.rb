control 'SV-220948' do
  title 'User Account Control must be configured to detect application installations and prompt for elevation.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting requires Windows to respond to application installation requests by prompting for credentials.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableInstallerDetection

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Detect application installations and prompt for elevation" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22663r555329_chk'
  tag severity: 'medium'
  tag gid: 'V-220948'
  tag rid: 'SV-220948r958518_rule'
  tag stig_id: 'WN10-SO-000260'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-22652r555330_fix'
  tag 'documentable'
  tag legacy: ['SV-78315', 'V-63825']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'EnableInstallerDetection' }
    its('EnableInstallerDetection') { should cmp 1 }
  end
end
