control 'SV-220978' do
  title 'The Manage auditing and security log user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Manage auditing and security log" user right can manage the security log and change auditing configurations. This could be used to clear evidence of tampering.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Manage auditing and security log" user right, this is a finding:

Administrators

If the organization has an "Auditors" group the assignment of this group to the user right would not be a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Manage auditing and security log" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22693r555419_chk'
  tag severity: 'medium'
  tag gid: 'V-220978'
  tag rid: 'SV-220978r958434_rule'
  tag stig_id: 'WN10-UR-000130'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-22682r555420_fix'
  tag 'documentable'
  tag legacy: ['SV-78417', 'V-63927']
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164', 'CCI-000171', 'CCI-001914']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a', 'AU-12 b', 'AU-12 (3)']

    describe security_policy do
      its('SeSecurityPrivilege') { should eq ['S-1-5-32-544'] }
    end
end
