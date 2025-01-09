control 'SV-220937' do
  title 'The system must be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc 'The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords. This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: NoLMHash

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22652r555296_chk'
  tag severity: 'high'
  tag gid: 'V-220937'
  tag rid: 'SV-220937r1016419_rule'
  tag stig_id: 'WN10-SO-000195'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-22641r555297_fix'
  tag 'documentable'
  tag legacy: ['SV-78287', 'V-63797']
  tag cci: ['CCI-004062', 'CCI-000196', 'CCI-000196']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (c)', 'IA-5 (1) (c)']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'NoLMHash' }
    its('NoLMHash') { should cmp 1 }
  end
end
