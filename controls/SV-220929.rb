control 'SV-220929' do
  title 'Anonymous enumeration of SAM accounts must not be allowed.'
  desc 'Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all accounts names, thus providing a list of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymousSAM

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22644r555272_chk'
  tag severity: 'high'
  tag gid: 'V-220929'
  tag rid: 'SV-220929r991589_rule'
  tag stig_id: 'WN10-SO-000145'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22633r555273_fix'
  tag 'documentable'
  tag legacy: ['SV-78235', 'V-63745']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'RestrictAnonymousSAM' }
    its('RestrictAnonymousSAM') { should cmp 1 }
  end
end
