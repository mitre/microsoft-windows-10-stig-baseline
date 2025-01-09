control 'SV-220961' do
  title 'The Change the system time user right must only be assigned to Administrators and Local Service and NT SERVICE\\autotimesvc.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Change the system time" user right can change the system time, which can impact authentication, as well as affect time stamps on event log entries.

The NT SERVICE\\autotimesvc is added in v1909 cumulative update.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Change the system time" user right, this is a finding:

Administrators
LOCAL SERVICE
NT SERVICE\\autotimesvc is added in v1909 cumulative update.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Change the system time" to only include the following groups or accounts:

Administrators
LOCAL SERVICE
NT SERVICE\\autotimesvc is added in v1909 cumulative update.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22676r555368_chk'
  tag severity: 'medium'
  tag gid: 'V-220961'
  tag rid: 'SV-220961r958726_rule'
  tag stig_id: 'WN10-UR-000035'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22665r555369_fix'
  tag 'documentable'
  tag legacy: ['V-63855', 'SV-78345']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

    describe security_policy do
      its('SeSystemtimePrivilege') { should be_in ['S-1-5-32-544', 'S-1-5-19'] }
    end
end
