control 'SV-220982' do
  title 'The Restore files and directories user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Restore files and directories" user right can circumvent file and directory permissions and could allow access to sensitive data. It could also be used to over-write more current data.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Restore files and directories" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Restore files and directories" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22697r555431_chk'
  tag severity: 'medium'
  tag gid: 'V-220982'
  tag rid: 'SV-220982r958726_rule'
  tag stig_id: 'WN10-UR-000160'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22686r555432_fix'
  tag 'documentable'
  tag legacy: ['V-63939', 'SV-78429']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

    describe security_policy do
      its('SeRestorePrivilege') { should eq ['S-1-5-32-544'] }
    end
end
