# -*- encoding : utf-8 -*-

control 'V-63415' do
  title 'The password history must be configured to 24 passwords remembered.'
  desc  "A system is more vulnerable to unauthorized access when system users
        recycle the same password several times without being required to change a
        password to a unique password on a regularly scheduled basis.  This enables
        users to effectively negate the purpose of mandating periodic password changes.
        The default value is 24 for Windows domain systems.  DoD has decided this is
        the appropriate value for all Windows systems."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AC-000020'
  tag gid: 'V-63415'
  tag rid: 'SV-77905r2_rule'
  tag stig_id: 'WN10-AC-000020'
  tag fix_id: 'F-69343r1_fix'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)', 'Rev_4']
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

      If the value for \"Enforce password history\" is less than #{input('pass_hist_size')} passwords
      remembered, this is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Account Policies >> Password Policy >>
      \"Enforce password history\" to #{input('pass_hist_size')} passwords remembered."

  describe security_policy do
    its('PasswordHistorySize') { should be >= input('pass_hist_size') }
  end
end

