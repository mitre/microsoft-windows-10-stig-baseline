# -*- encoding : utf-8 -*-

control 'V-63619' do
  title 'The built-in administrator account must be renamed.'
  desc  "The built-in administrator account is a well-known account subject to
        attack.  Renaming this account to an unidentified name improves the protection
        of this account and the system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000020'
  tag gid: 'V-63619'
  tag rid: 'SV-78109r1_rule'
  tag stig_id: 'WN10-SO-000020'
  tag fix_id: 'F-69551r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']
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
      >> Security Settings >> Local Policies >> Security Options.

      If the value for \"Accounts: Rename administrator account\" is set to
      \"Administrator\", this is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Accounts: Rename administrator account\" to a name other than
      \"Administrator\"."

  describe user('Administrator') do
    it { should_not exist }
  end
end

