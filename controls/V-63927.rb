# -*- encoding : utf-8 -*-

control 'V-63927' do
  title "The Manage auditing and security log user right must only be assigned
        to the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Manage auditing and security log\" user right can
        manage the security log and change auditing configurations. This could be used
        to clear evidence of tampering."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000130'
  tag gid: 'V-63927'
  tag rid: 'SV-78417r1_rule'
  tag stig_id: 'WN10-UR-000130'
  tag fix_id: 'F-69855r1_fix'
  tag cci: %w[CCI-000162 CCI-000163 CCI-000164 CCI-000171 CCI-001914]
  tag nist: ['AU-9', 'AU-9', 'AU-9', 'AU-12 b', 'AU-12 (3)', 'Rev_4']
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

      If any groups or accounts other than the following are granted the \"Manage
      auditing and security log\" user right, this is a finding:

      Administrators

      If the organization has an \"Auditors\" group the assignment of this group to
      the user right would not be a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Manage auditing and security log\" to only include the following groups or
      accounts:

      Administrators"

    describe security_policy do
      its('SeSecurityPrivilege') { should eq ['S-1-5-32-544'] }
    end
end

