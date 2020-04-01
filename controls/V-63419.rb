# -*- encoding : utf-8 -*-

control 'V-63419' do
  title 'The maximum password age must be configured to 60 days or less.'
  desc  "The longer a password is in use, the greater the opportunity for
        someone to gain unauthorized knowledge of the passwords.   Scheduled changing
        of passwords hinders the ability of unauthorized system users to crack
        passwords and gain access to a system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AC-000025'
  tag gid: 'V-63419'
  tag rid: 'SV-77909r1_rule'
  tag stig_id: 'WN10-AC-000025'
  tag fix_id: 'F-69347r1_fix'
  tag cci: ['CCI-000199']
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

      If the value for the \"Maximum password age\" is greater than #{input('max_pass_age')} days, this
      is a finding.  If the value is set to \"0\" (never expires), this is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Account Policies >> Password Policy >>
      \"Maximum Password Age\" to #{input('max_pass_age')} days or less (excluding \"0\" which is
      unacceptable)."

  describe security_policy do
    its('MaximumPasswordAge') { should be <= input('max_pass_age') }
  end
  describe "The password policy is set to expire after #{input('max_pass_age')}" do
    subject { security_policy }
    its('MaximumPasswordAge') { should be_positive }
  end
end

