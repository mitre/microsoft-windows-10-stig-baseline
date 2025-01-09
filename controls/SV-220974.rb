control 'SV-220974' do
  title 'The Force shutdown from a remote system user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Force shutdown from a remote system" user right can remotely shut down a system which could result in a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Force shutdown from a remote system" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Force shutdown from a remote system" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22689r555407_chk'
  tag severity: 'medium'
  tag gid: 'V-220974'
  tag rid: 'SV-220974r958726_rule'
  tag stig_id: 'WN10-UR-000100'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22678r555408_fix'
  tag 'documentable'
  tag legacy: ['SV-78373', 'V-63883']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

    describe security_policy do
      its('SeRemoteShutdownPrivilege') { should eq ['S-1-5-32-544'] }
    end
end
