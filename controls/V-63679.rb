# -*- encoding : utf-8 -*-

control 'V-63679' do
  title 'Administrator accounts must not be enumerated during elevation.'
  desc  "Enumeration of administrator accounts when elevating can provide part
        of the logon information to an unauthorized user.  This setting configures the
        system to always require users to type in a username and password to elevate a
        running application."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000200'
  tag gid: 'V-63679'
  tag rid: 'SV-78169r1_rule'
  tag stig_id: 'WN10-CC-000200'
  tag fix_id: 'F-69607r1_fix'
  tag cci: ['CCI-001084']
  tag nist: %w[SC-3 Rev_4]
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
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI\\

      Value Name: EnumerateAdministrators

      Value Type: REG_DWORD
      Value: 0"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Credential User Interface >>
      \"Enumerate administrator accounts on elevation\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI') do
    it { should have_property 'EnumerateAdministrators' }
    its('EnumerateAdministrators') { should cmp 0 }
  end
end

