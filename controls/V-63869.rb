# -*- encoding : utf-8 -*-

control 'V-63869' do
  title "The Debug programs user right must only be assigned to the
        Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Debug Programs\" user right can attach a debugger to
        any process or to the kernel, providing complete access to sensitive and
        critical operating system components.  This right is given to Administrators in
        the default configuration."

  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-UR-000065'
  tag gid: 'V-63869'
  tag rid: 'SV-78359r1_rule'
  tag stig_id: 'WN10-UR-000065'
  tag fix_id: 'F-69797r1_fix'
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

      If any groups or accounts other than the following are granted the \"Debug
      Programs\" user right, this is a finding:

      Administrators"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Debug programs\" to only include the following groups or accounts:

      Administrators"

    describe security_policy do
      its('SeDebugPrivilege') { should eq ['S-1-5-32-544'] }
    end
end

