# -*- encoding : utf-8 -*-

control 'V-63889' do
  title "The Impersonate a client after authentication user right must only be
        assigned to Administrators, Service, Local Service, and Network Service."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        The \"Impersonate a client after authentication\" user right allows a
        program to impersonate another user or account to run on their behalf. An
        attacker could potentially use this to elevate privileges."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000110'
  tag gid: 'V-63889'
  tag rid: 'SV-78379r1_rule'
  tag stig_id: 'WN10-UR-000110'
  tag fix_id: 'F-69817r1_fix'
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

        If any groups or accounts other than the following are granted the
        \"Impersonate a client after authentication\" user right, this is a finding:

        Administrators
        LOCAL SERVICE
        NETWORK SERVICE
        SERVICE"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
        Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
        \"Impersonate a client after authentication\" to only include the following
        groups or accounts:

        Administrators
        LOCAL SERVICE
        NETWORK SERVICE
        SERVICE"

    describe security_policy do
      its('SeAuditPrivilege') { should be_in ['S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6'] }
    end
end

