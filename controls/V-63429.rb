# -*- encoding : utf-8 -*-

control 'V-63429' do
  title 'Reversible password encryption must be disabled.'
  desc  "Storing passwords using reversible encryption is essentially the same
        as storing clear-text versions of the passwords. For this reason, this policy
        must never be enabled."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-AC-000045'
  tag gid: 'V-63429'
  tag rid: 'SV-77919r1_rule'
  tag stig_id: 'WN10-AC-000045'
  tag fix_id: 'F-69357r1_fix'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)', 'Rev_4']
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
      >> Security Settings >> Account Policies >> Password Policy.

      If the value for \"Store password using reversible encryption\" is not set to
      \"Disabled\", this is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Account Policies >> Password Policy >> \"Store
      passwords using reversible encryption\" to \"Disabled\"."

  describe security_policy do
    its('ClearTextPassword') { should eq 0 }
  end
end

