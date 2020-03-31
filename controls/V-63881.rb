# -*- encoding : utf-8 -*-

control 'V-63881' do
  title "The Enable computer and user accounts to be trusted for delegation
        user right must not be assigned to any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        The \"Enable computer and user accounts to be trusted for delegation\" user
        right allows the \"Trusted for Delegation\" setting to be changed. This could
        potentially allow unauthorized users to impersonate other users."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000095'
  tag gid: 'V-63881'
  tag rid: 'SV-78371r1_rule'
  tag stig_id: 'WN10-UR-000095'
  tag fix_id: 'F-69809r1_fix'
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

      If any groups or accounts are granted the \"Enable computer and user accounts
      to be trusted for delegation\" user right, this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Enable computer and user accounts to be trusted for delegation\" to be
      defined but containing no entries (blank)."

  describe security_policy do
    its('SeEnableDelegationPrivilege') { should eq [] }
  end
end

