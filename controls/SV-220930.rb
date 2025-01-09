control 'SV-220930' do
  title 'Anonymous enumeration of shares must be restricted.'
  desc 'Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared resources can provide a map of potential points to attack the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictAnonymous

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts and shares" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22645r555275_chk'
  tag severity: 'high'
  tag gid: 'V-220930'
  tag rid: 'SV-220930r958524_rule'
  tag stig_id: 'WN10-SO-000150'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-22634r555276_fix'
  tag 'documentable'
  tag legacy: ['V-63749', 'SV-78239']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'RestrictAnonymous' }
    its('RestrictAnonymous') { should cmp 1 }
  end
end
