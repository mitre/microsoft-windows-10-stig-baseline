control 'SV-220967' do
  title 'The Debug programs user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Debug Programs" user right can attach a debugger to any process or to the kernel, providing complete access to sensitive and critical operating system components.  This right is given to Administrators in the default configuration.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Debug Programs" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Debug programs" to only include the following groups or accounts:

Administrators'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22682r555386_chk'
  tag severity: 'high'
  tag gid: 'V-220967'
  tag rid: 'SV-220967r958726_rule'
  tag stig_id: 'WN10-UR-000065'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22671r555387_fix'
  tag 'documentable'
  tag legacy: ['V-63869', 'SV-78359']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

    describe security_policy do
      its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
    end
end
