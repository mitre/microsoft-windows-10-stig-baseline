# -*- encoding : utf-8 -*-

control 'V-63865' do
  title "The Create symbolic links user right must only be assigned to the
        Administrators group."
  desc  "Inappropriate granting of user rights can provide system,
        administrative, and other high level capabilities.

        Accounts with the \"Create symbolic links\" user right can create pointers
        to other objects, which could potentially expose the system to attack."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UR-000060'
  tag gid: 'V-63865'
  tag rid: 'SV-78355r2_rule'
  tag stig_id: 'WN10-UR-000060'
  tag fix_id: 'F-69793r1_fix'
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
      symbolic links\" user right, this is a finding:

      Administrators

      If the workstation has an approved use of Hyper-V, such as being used as a
      dedicated admin workstation using Hyper-V to separate administration and
      standard user functions, \"NT VIRTUAL MACHINES\\VIRTUAL MACHINE\" may be
      assigned this user right and is not a finding."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
      \"Create symbolic links\" to only include the following groups or accounts:

      Administrators"

    describe security_policy do
      its('SeCreateSymbolicLinkPrivilege') { should eq ['S-1-5-32-544'] }
    end
end

