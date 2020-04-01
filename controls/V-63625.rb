# -*- encoding : utf-8 -*-

control 'V-63625' do
  title 'The built-in guest account must be renamed.'
  desc  "The built-in guest account is a well-known user account on all Windows
        systems and, as initially installed, does not require a password.  This can
        allow access to system resources by unauthorized users.  Renaming this account
        to an unidentified name improves the protection of this account and the system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000025'
  tag gid: 'V-63625'
  tag rid: 'SV-78115r1_rule'
  tag stig_id: 'WN10-SO-000025'
  tag fix_id: 'F-69555r1_fix'
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

      If the value for \"Accounts: Rename guest account\" is set to \"Guest\", this
      is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Accounts: Rename guest account\" to a name other than \"Guest\"."

  describe user('Guest') do
    it { should_not exist }
  end
end

