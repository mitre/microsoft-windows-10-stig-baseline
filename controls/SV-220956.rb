control 'SV-220956' do
  title 'The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Access Credential Manager as a trusted caller" user right may be able to retrieve the credentials of other accounts from Credential Manager.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Access Credential Manager as a trusted caller" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access Credential Manager as a trusted caller" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22671r555353_chk'
  tag severity: 'medium'
  tag gid: 'V-220956'
  tag rid: 'SV-220956r958726_rule'
  tag stig_id: 'WN10-UR-000005'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22660r555354_fix'
  tag 'documentable'
  tag legacy: ['V-63843', 'SV-78333']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
end
