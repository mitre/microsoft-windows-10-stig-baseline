control 'SV-220934' do
  title 'NTLM must be prevented from falling back to a Null session.'
  desc 'NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\MSV1_0\\

Value Name: allownullsessionfallback

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Allow LocalSystem NULL session fallback" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22649r555287_chk'
  tag severity: 'medium'
  tag gid: 'V-220934'
  tag rid: 'SV-220934r991589_rule'
  tag stig_id: 'WN10-SO-000180'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22638r555288_fix'
  tag 'documentable'
  tag legacy: ['V-63765', 'SV-78255']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0') do
    it { should have_property 'allownullsessionfallback' }
    its('allownullsessionfallback') { should cmp 0 }
  end
end
