control 'SV-220959' do
  title 'The Allow log on locally user right must only be assigned to the Administrators and Users groups.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Allow log on locally" user right can log on interactively to a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Allow log on locally" user right, this is a finding:

Administrators
Users'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Allow log on locally" to only include the following groups or accounts:

Administrators
Users'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22674r555362_chk'
  tag severity: 'medium'
  tag gid: 'V-220959'
  tag rid: 'SV-220959r958472_rule'
  tag stig_id: 'WN10-UR-000025'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-22663r555363_fix'
  tag 'documentable'
  tag legacy: ['V-63851', 'SV-78341']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

    describe security_policy do
      its('SeInteractiveLogonRight') { should be_in ['S-1-5-32-544', 'S-1-5-32-545'] }
    end
end
