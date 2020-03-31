# -*- encoding : utf-8 -*-

control 'V-63651' do
  title 'Solicited Remote Assistance must not be allowed.'
  desc  "Remote assistance allows another user to view or take control of the
        local session of a user.  Solicited assistance is help that is specifically
        requested by the local user.  This may allow unauthorized parties access to the
        resources on the computer."

  impact 0.7

  tag severity: 'high'
  tag gtitle: 'WN10-CC-000155'
  tag gid: 'V-63651'
  tag rid: 'SV-78141r1_rule'
  tag stig_id: 'WN10-CC-000155'
  tag fix_id: 'F-69581r1_fix'
  tag cci: ['CCI-001090']
  tag nist: %w[SC-4 Rev_4]
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

      Value Name: fAllowToGetHelp

      Value Type: REG_DWORD
      Value: 0"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> Remote Assistance >> \"Configure
      Solicited Remote Assistance\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'fAllowToGetHelp' }
    its('fAllowToGetHelp') { should cmp 0 }
  end
end

