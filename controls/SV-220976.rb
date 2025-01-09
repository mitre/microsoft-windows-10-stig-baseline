control 'SV-220976' do
  title 'The Load and unload device drivers user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Load and unload device drivers" user right allows device drivers to dynamically be loaded on a system by a user. This could potentially be used to install malicious code by an attacker.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Load and unload device drivers" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Load and unload device drivers" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22691r555413_chk'
  tag severity: 'medium'
  tag gid: 'V-220976'
  tag rid: 'SV-220976r958726_rule'
  tag stig_id: 'WN10-UR-000120'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22680r555414_fix'
  tag 'documentable'
  tag legacy: ['SV-78407', 'V-63917']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

      desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Load and unload device drivers\" to only include the following groups or
      accounts:

      Administrators"

    describe security_policy do
      its('SeLoadDriverPrivilege') { should eq ['S-1-5-32-544'] }
    end
end
