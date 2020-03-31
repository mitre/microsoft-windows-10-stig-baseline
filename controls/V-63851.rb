# -*- encoding : utf-8 -*-

control 'V-63851' do
  title 'The Allow log on locally user right must only be assigned to the Administrators and Users groups.'
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high-level capabilities.

        Accounts with the \"Allow log on locally\" user right can log on
        interactively to a system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000025'
  tag gid: 'V-63851'
  tag rid: 'SV-78341r2_rule'
  tag stig_id: 'WN10-UR-000025'
  tag fix_id: 'F-88439r1_fix'
  tag cci: ['CCI-000213']
  tag nist: %w[AC-3 Rev_4]
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

      If any groups or accounts other than the following are granted the \"Allow log
      on locally\" user right, this is a finding:

      Administrators
      Users"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Allow log on locally\" to only include the following groups or accounts:

      Administrators
      Users"

    describe security_policy do
      its('SeInteractiveLogonRight') { should be_in ['S-1-5-32-544', 'S-1-5-32-545'] }
    end
end

