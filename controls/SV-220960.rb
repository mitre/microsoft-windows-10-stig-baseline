control 'SV-220960' do
  title 'The Back up files and directories user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Back up files and directories" user right can circumvent file and directory permissions and could allow access to sensitive data."'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Back up files and directories" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Back up files and directories" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22675r555365_chk'
  tag severity: 'medium'
  tag gid: 'V-220960'
  tag rid: 'SV-220960r958726_rule'
  tag stig_id: 'WN10-UR-000030'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22664r555366_fix'
  tag 'documentable'
  tag legacy: ['V-63853', 'SV-78343']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

    describe security_policy do
      its('SeBackupPrivilege') { should eq ['S-1-5-32-544'] }
    end
end
