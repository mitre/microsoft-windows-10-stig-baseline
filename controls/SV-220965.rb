control 'SV-220965' do
  title 'The Create permanent shared objects user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Create permanent shared objects" user right could expose sensitive data by creating shared objects.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Create permanent shared objects" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create permanent shared objects" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22680r555380_chk'
  tag severity: 'medium'
  tag gid: 'V-220965'
  tag rid: 'SV-220965r958726_rule'
  tag stig_id: 'WN10-UR-000055'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22669r555381_fix'
  tag 'documentable'
  tag legacy: ['V-63863', 'SV-78353']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  describe security_policy do
    its('SeCreatePermanentPrivilege') { should eq [] }
  end
end
