control 'SV-220980' do
  title 'The Perform volume maintenance tasks user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Perform volume maintenance tasks" user right can manage volume and disk configurations. They could potentially delete volumes, resulting in, data loss or a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Perform volume maintenance tasks" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Perform volume maintenance tasks" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22695r555425_chk'
  tag severity: 'medium'
  tag gid: 'V-220980'
  tag rid: 'SV-220980r958726_rule'
  tag stig_id: 'WN10-UR-000145'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22684r555426_fix'
  tag 'documentable'
  tag legacy: ['SV-78423', 'V-63933']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

    describe security_policy do
      its('SeManageVolumePrivilege') { should eq ['S-1-5-32-544'] }
    end
end
