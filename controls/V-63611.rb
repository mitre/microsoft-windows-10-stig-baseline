# -*- encoding : utf-8 -*-

control 'V-63611' do
  title 'The built-in guest account must be disabled.'
  desc  "A system faces an increased vulnerability threat if the built-in guest
        account is not disabled.  This account is a known account that exists on all
        Windows systems and cannot be deleted.  This account is initialized during the
        installation of the operating system with no password assigned."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000010'
  tag gid: 'V-63611'
  tag rid: 'SV-78101r1_rule'
  tag stig_id: 'WN10-SO-000010'
  tag fix_id: 'F-69541r1_fix'
  tag cci: ['CCI-000804']
  tag nist: %w[IA-8 Rev_4]
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

      If the value for \"Accounts: Guest account status\" is not set to \"Disabled\",
      this is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Accounts: Guest account status\" to \"Disabled\"."

  describe security_policy do
    its('EnableGuestAccount') { should cmp 0 }
  end
end

