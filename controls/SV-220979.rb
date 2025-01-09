control 'SV-220979' do
  title 'The Modify firmware environment values user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Modify firmware environment values" user right can change hardware configuration environment variables. This could result in hardware failures or a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Modify firmware environment values" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Modify firmware environment values" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22694r555422_chk'
  tag severity: 'medium'
  tag gid: 'V-220979'
  tag rid: 'SV-220979r958726_rule'
  tag stig_id: 'WN10-UR-000140'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22683r555423_fix'
  tag 'documentable'
  tag legacy: ['V-63931', 'SV-78421']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

    describe security_policy do
      its('SeSystemEnvironmentPrivilege') { should eq ['S-1-5-32-544'] }
    end
end
