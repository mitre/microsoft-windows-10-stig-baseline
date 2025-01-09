control 'SV-220939' do
  title 'The system must be configured to the required LDAP client signing level.'
  desc 'This setting controls the signing requirements for LDAP clients.  This setting must be set to Negotiate signing or Require signing, depending on the environment and type of LDAP server in use.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LDAP\\

Value Name: LDAPClientIntegrity

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: LDAP client signing requirements" to "Negotiate signing" at a minimum.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22654r555302_chk'
  tag severity: 'medium'
  tag gid: 'V-220939'
  tag rid: 'SV-220939r991589_rule'
  tag stig_id: 'WN10-SO-000210'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22643r555303_fix'
  tag 'documentable'
  tag legacy: ['SV-78293', 'V-63803']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LDAP') do
    it { should have_property 'LDAPClientIntegrity' }
    its('LDAPClientIntegrity') { should cmp 1 }
  end
end
