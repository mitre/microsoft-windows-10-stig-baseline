# -*- encoding : utf-8 -*-

control 'V-63859' do
  title "The Create a token object user right must not be assigned to any
        groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        The \"Create a token object\" user right allows a process to create an
        access token. This could be used to provide elevated rights and compromise a
        system."

  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-UR-000045'
  tag gid: 'V-63859'
  tag rid: 'SV-78349r1_rule'
  tag stig_id: 'WN10-UR-000045'
  tag fix_id: 'F-69787r2_fix'
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

      If any groups or accounts are granted the \"Create a token object\" user right,
      this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Create a token object\" to be defined but containing no entries (blank)."

  describe security_policy do
    its('SeCreateTokenPrivilege') { should eq [] }
  end
end

