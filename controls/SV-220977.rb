control 'SV-220977' do
  title 'The Lock pages in memory user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Lock pages in memory" user right allows physical memory to be assigned to processes, which could cause performance issues or a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts are granted the "Lock pages in memory" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Lock pages in memory" to be defined but containing no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22692r555416_chk'
  tag severity: 'medium'
  tag gid: 'V-220977'
  tag rid: 'SV-220977r958726_rule'
  tag stig_id: 'WN10-UR-000125'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22681r555417_fix'
  tag 'documentable'
  tag legacy: ['V-63925', 'SV-78415']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq [] }
  end
end
