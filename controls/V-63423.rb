# -*- encoding : utf-8 -*-

control 'V-63423' do
  title 'Passwords must, at a minimum, be 14 characters.'
  desc  "Information systems not protected with strong password schemes
      (including passwords of minimum length) provide the opportunity for anyone to
      crack the password, thus gaining access to the system and compromising the
      device, information, or the local network."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AC-000035'
  tag gid: 'V-63423'
  tag rid: 'SV-77913r1_rule'
  tag stig_id: 'WN10-AC-000035'
  tag fix_id: 'F-69351r1_fix'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)', 'Rev_4']
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

      If the value for the \"Minimum password length,\" is less than #{input('min_pass_len')}
      characters, this is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Account Policies >> Password Policy >>
      \"Minimum password length\" to #{input('min_pass_len')} characters."

  describe security_policy do
    its('MinimumPasswordLength') { should be >= input('min_pass_len') }
  end
end

