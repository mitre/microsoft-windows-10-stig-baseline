# -*- encoding : utf-8 -*-

control 'V-63843' do
  title "The Access Credential Manager as a trusted caller user right must not
        be assigned to any groups or accounts."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Access Credential Manager as a trusted caller\" user
        right may be able to retrieve the credentials of other accounts from Credential
        Manager."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000005'
  tag gid: 'V-63843'
  tag rid: 'SV-78333r1_rule'
  tag stig_id: 'WN10-UR-000005'
  tag fix_id: 'F-69771r1_fix'
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

      If any groups or accounts are granted the \"Access Credential Manager as a
      trusted caller\" user right, this is a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Access Credential Manager as a trusted caller\" to be defined but containing
      no entries (blank)."

  describe security_policy do
    its('SeTrustedCredManAccessPrivilege') { should eq [] }
  end
end

