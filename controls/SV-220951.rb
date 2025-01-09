control 'SV-220951' do
  title 'User Account Control must virtualize file and registry write failures to per-user locations.'
  desc 'User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including administrative accounts, unless authorized.  This setting configures non-UAC compliant applications to run in virtualized file and registry entries in per-user locations, allowing them to run.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

Value Name: EnableVirtualization

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "User Account Control: Virtualize file and registry write failures to per-user locations" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22666r555338_chk'
  tag severity: 'medium'
  tag gid: 'V-220951'
  tag rid: 'SV-220951r958518_rule'
  tag stig_id: 'WN10-SO-000275'
  tag gtitle: 'SRG-OS-000134-GPOS-00068'
  tag fix_id: 'F-22655r555339_fix'
  tag 'documentable'
  tag legacy: ['SV-78321', 'V-63831']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'EnableVirtualization' }
    its('EnableVirtualization') { should cmp 1 }
  end
end
