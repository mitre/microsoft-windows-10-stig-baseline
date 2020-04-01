# -*- encoding : utf-8 -*-

control 'V-63861' do
  title "The Create global objects user right must only be assigned to
        Administrators, Service, Local Service, and Network Service."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Create global objects\" user right can create objects
        that are available to all sessions, which could affect processes in other
        users' sessions."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000050'
  tag gid: 'V-63861'
  tag rid: 'SV-78351r1_rule'
  tag stig_id: 'WN10-UR-000050'
  tag fix_id: 'F-69789r1_fix'
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

        If any groups or accounts other than the following are granted the \"Create
        global objects\" user right, this is a finding:

        Administrators
        LOCAL SERVICE
        NETWORK SERVICE
        SERVICE"
  
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
        Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
        \"Create global objects\" to only include the following groups or accounts:

        Administrators
        LOCAL SERVICE
        NETWORK SERVICE
        SERVICE"

     describe security_policy do
      its('SeCreateGlobalPrivilege') { should be_in ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
    end
end

