control 'SV-220958' do
  title 'The Act as part of the operating system user right must not be assigned to any groups or accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Act as part of the operating system" user right can assume the identity of any user and gain access to resources that user is authorized to access.  Any accounts with this right can take complete control of a system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts (to include administrators), are granted the "Act as part of the operating system" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Act as part of the operating system" to be defined but containing no entries (blank).'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22673r555359_chk'
  tag severity: 'high'
  tag gid: 'V-220958'
  tag rid: 'SV-220958r958726_rule'
  tag stig_id: 'WN10-UR-000015'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22662r555360_fix'
  tag 'documentable'
  tag legacy: ['SV-78337', 'V-63847']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  describe security_policy do
    its('SeTcbPrivilege') { should eq [] }
  end
end
