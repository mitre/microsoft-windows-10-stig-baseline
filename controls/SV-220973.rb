control 'SV-220973' do
  title 'The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for Delegation" setting to be changed. This could potentially allow unauthorized users to impersonate other users.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Enable computer and user accounts to be trusted for delegation" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Enable computer and user accounts to be trusted for delegation" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22688r555404_chk'
  tag severity: 'medium'
  tag gid: 'V-220973'
  tag rid: 'SV-220973r958726_rule'
  tag stig_id: 'WN10-UR-000095'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22677r555405_fix'
  tag 'documentable'
  tag legacy: ['V-63881', 'SV-78371']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  describe security_policy do
    its('SeEnableDelegationPrivilege') { should eq [] }
  end
end
