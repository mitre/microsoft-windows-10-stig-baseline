# -*- encoding : utf-8 -*-

control 'V-63855' do
  title "The Change the system time user right must only be assigned to
        Administrators and Local Service."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Change the system time\" user right can change the
        system time, which can impact authentication, as well as affect time stamps on
        event log entries."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000035'
  tag gid: 'V-63855'
  tag rid: 'SV-78345r1_rule'
  tag stig_id: 'WN10-UR-000035'
  tag fix_id: 'F-69783r1_fix'
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

      If any groups or accounts other than the following are granted the \"Change the
      system time\" user right, this is a finding:

      Administrators
      LOCAL SERVICE"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Change the system time\" to only include the following groups or accounts:

      Administrators
      LOCAL SERVICE"

    describe security_policy do
      its('SeSystemtimePrivilege') { should be_in ['S-1-5-32-544', 'S-1-5-19'] }
    end
end

