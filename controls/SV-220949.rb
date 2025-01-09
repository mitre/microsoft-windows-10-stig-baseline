control 'SV-220949' do
  title 'User Account Control must only elevate UIAccess applications that are installed in secure locations.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures Windows to only allow applications installed in a secure location on the file system, such as the Program Files or the Windows\\System32 folders, to run with elevated privileges.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableSecureUIAPaths

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Only elevate UIAccess applications that are installed in secure locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22664r555332_chk'
  tag severity: 'medium'
  tag gid: 'V-220949'
  tag rid: 'SV-220949r958518_rule'
  tag stig_id: 'WN10-SO-000265'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-22653r555333_fix'
  tag 'documentable'
  tag legacy: ['V-63827', 'SV-78317']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'EnableSecureUIAPaths' }
    its('EnableSecureUIAPaths') { should cmp 1 }
  end
end
