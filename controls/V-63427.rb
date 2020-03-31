# -*- encoding : utf-8 -*-

control 'V-63427' do
  title 'The built-in Microsoft password complexity filter must be enabled.'
  desc  "The use of complex passwords increases their strength against guessing
        and brute-force attacks.  This setting configures the system to verify that
        newly created passwords conform to the Windows password complexity policy."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AC-000040'
  tag gid: 'V-63427'
  tag rid: 'SV-77917r1_rule'
  tag stig_id: 'WN10-AC-000040'
  tag fix_id: 'F-69355r1_fix'
  tag cci: %w[CCI-000192 CCI-000193 CCI-000194 CCI-001619]
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)',
             'Rev_4']
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

      If the value for \"Password must meet complexity requirements\" is not set to
      \"Enabled\", this is a finding.

      If the site is using a password filter that requires this setting be set to
      \"Disabled\" for the filter to be used, this would not be considered a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Account Policies >> Password Policy >>
      \"Password must meet complexity requirements\" to \"Enabled\"."

  describe security_policy do
    its('PasswordComplexity') { should eq input('enable_pass_complexity') }
  end
end

