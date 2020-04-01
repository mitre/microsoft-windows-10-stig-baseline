# -*- encoding : utf-8 -*-

control 'V-63931' do
  title "The Modify firmware environment values user right must only be
        assigned to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Modify firmware environment values\" user right can
        change hardware configuration environment variables. This could result in
        hardware failures or a DoS."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000140'
  tag gid: 'V-63931'
  tag rid: 'SV-78421r1_rule'
  tag stig_id: 'WN10-UR-000140'
  tag fix_id: 'F-69859r1_fix'
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

      If any groups or accounts other than the following are granted the \"Modify
      firmware environment values\" user right, this is a finding:

      Administrators"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Modify firmware environment values\" to only include the following groups or
      accounts:

      Administrators"

    describe security_policy do
      its('SeSystemEnvironmentPrivilege') { should eq ['S-1-5-32-544'] }
    end
end

