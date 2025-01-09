control 'SV-220931' do
  title 'The system must be configured to prevent anonymous users from having the same rights as the Everyone group.'
  desc 'Access by anonymous users must be restricted.  If this setting is enabled, then anonymous users have the same rights and permissions as the built-in Everyone group.  Anonymous users must not have these permissions or rights.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: EveryoneIncludesAnonymous

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Let Everyone permissions apply to anonymous users" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22646r555278_chk'
  tag severity: 'medium'
  tag gid: 'V-220931'
  tag rid: 'SV-220931r991589_rule'
  tag stig_id: 'WN10-SO-000160'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22635r555279_fix'
  tag 'documentable'
  tag legacy: ['V-63755', 'SV-78245']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'EveryoneIncludesAnonymous' }
    its('EveryoneIncludesAnonymous') { should cmp 0 }
  end
end
