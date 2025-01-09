control 'SV-220983' do
  title 'The Take ownership of files or other objects user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Take ownership of files or other objects" user right can take ownership of objects and make changes.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Take ownership of files or other objects" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Take ownership of files or other objects" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22698r555434_chk'
  tag severity: 'medium'
  tag gid: 'V-220983'
  tag rid: 'SV-220983r958726_rule'
  tag stig_id: 'WN10-UR-000165'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22687r555435_fix'
  tag 'documentable'
  tag legacy: ['SV-78431', 'V-63941']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

    describe security_policy do
      its('SeTakeOwnershipPrivilege') { should eq ['S-1-5-32-544'] }
    end
end
