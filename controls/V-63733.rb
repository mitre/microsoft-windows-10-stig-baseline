# -*- encoding : utf-8 -*-

control 'V-63733' do
  title "Remote Desktop Services must always prompt a client for passwords upon
        connection."
  desc  "This setting controls the ability of users to supply passwords
        automatically as part of their remote desktop connection.  Disabling this
        setting would allow anyone to use the stored credentials in a connection item
        to connect to the terminal server."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000280'
  tag gid: 'V-63733'
  tag rid: 'SV-78223r1_rule'
  tag stig_id: 'WN10-CC-000280'
  tag fix_id: 'F-69661r1_fix'
  tag cci: ['CCI-002038']
  tag nist: %w[IA-11 Rev_4]
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
  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

      Value Name: fPromptForPassword

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Remote Desktop Services >>
      Remote Desktop Session Host >> Security >> \"Always prompt for password upon
      connection\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'fPromptForPassword' }
    its('fPromptForPassword') { should cmp 1 }
  end
end

