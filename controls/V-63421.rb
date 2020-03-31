# -*- encoding : utf-8 -*-

control 'V-63421' do
  title 'The minimum password age must be configured to at least 1 day.'
  desc  "Permitting passwords to be changed in immediate succession within the
        same day allows users to cycle passwords through their history database.  This
        enables users to effectively negate the purpose of mandating periodic password
        changes."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AC-000030'
  tag gid: 'V-63421'
  tag rid: 'SV-77911r1_rule'
  tag stig_id: 'WN10-AC-000030'
  tag fix_id: 'F-69349r1_fix'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)', 'Rev_4']
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

        If the value for the \"Minimum password age\" is less than #{input('min_pass_age')} day, this is a
        finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
        Settings >> Security Settings >> Account Policies >> Password Policy >>
        \"Minimum Password Age\" to at least #{input('min_pass_age')} day."

  describe security_policy do
    its('MinimumPasswordAge') { should be >= input('min_pass_age') }
  end
end

