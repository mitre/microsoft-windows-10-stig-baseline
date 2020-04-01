# -*- encoding : utf-8 -*-

control 'V-63925' do
  title "The Lock pages in memory user right must not be assigned to any groups
        or accounts."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        The \"Lock pages in memory\" user right allows physical memory to be
        assigned to processes, which could cause performance issues or a DoS."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000125'
  tag gid: 'V-63925'
  tag rid: 'SV-78415r1_rule'
  tag stig_id: 'WN10-UR-000125'
  tag fix_id: 'F-69853r1_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)', 'Rev_4']
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: false
  tag mitigations: nil
  tag severity_override_guidance: false
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: nil
  desc "check", "Verify the effective setting in Local Group Policy Editor.
      Run \"gpedit.msc\".

      Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
      >> Security Settings >> Local Policies >> User Rights Assignment.

      If any groups or accounts are granted the \"Lock pages in memory\" user right,
      this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Lock pages in memory\" to be defined but containing no entries (blank)."

  describe security_policy do
    its('SeLockMemoryPrivilege') { should eq [] }
  end
end

