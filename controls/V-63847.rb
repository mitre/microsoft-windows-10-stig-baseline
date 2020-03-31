# -*- encoding : utf-8 -*-

control 'V-63847' do
  title "The Act as part of the operating system user right must not be
        assigned to any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Act as part of the operating system\" user right can
        assume the identity of any user and gain access to resources that user is
        authorized to access.  Any accounts with this right can take complete control
        of a system."

  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-UR-000015'
  tag gid: 'V-63847'
  tag rid: 'SV-78337r1_rule'
  tag stig_id: 'WN10-UR-000015'
  tag fix_id: 'F-69775r1_fix'
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

      If any groups or accounts (to include administrators), are granted the \"Act as
      part of the operating system\" user right, this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Act as part of the operating system\" to be defined but containing no entries
      (blank)."

  describe security_policy do
    its('SeTcbPrivilege') { should eq [] }
  end
end

