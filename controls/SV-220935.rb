control 'SV-220935' do
  title 'PKU2U authentication using online identities must be prevented.'
  desc 'PKU2U is a peer-to-peer authentication protocol.   This setting prevents online identities from authenticating to domain-joined systems.  Authentication will be centrally managed with Windows user accounts.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u\\

Value Name: AllowOnlineID

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Allow PKU2U authentication requests to this computer to use online identities" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22650r555290_chk'
  tag severity: 'medium'
  tag gid: 'V-220935'
  tag rid: 'SV-220935r991589_rule'
  tag stig_id: 'WN10-SO-000185'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22639r555291_fix'
  tag 'documentable'
  tag legacy: ['SV-78257', 'V-63767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\pku2u') do
    it { should have_property 'AllowOnlineID' }
    its('AllowOnlineID') { should cmp 0 }
  end
end
