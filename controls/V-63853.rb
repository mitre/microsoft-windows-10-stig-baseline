# -*- encoding : utf-8 -*-

control 'V-63853' do
  title "The Back up files and directories user right must only be assigned to
        the Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Back up files and directories\" user right can
        circumvent file and directory permissions and could allow access to sensitive
        data."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000030'
  tag gid: 'V-63853'
  tag rid: 'SV-78343r1_rule'
  tag stig_id: 'WN10-UR-000030'
  tag fix_id: 'F-69781r1_fix'
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

      If any groups or accounts other than the following are granted the \"Back up
      files and directories\" user right, this is a finding:

      Administrators"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Back up files and directories\" to only include the following groups or
      accounts:

      Administrators"

    describe security_policy do
      its('SeBackupPrivilege') { should eq ['S-1-5-32-544'] }
    end
end

