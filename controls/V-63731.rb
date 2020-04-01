# -*- encoding : utf-8 -*-

control 'V-63731' do
  title "Local drives must be prevented from sharing with Remote Desktop
        Session Hosts."
  desc  "Preventing users from sharing the local drives on their client
        computers to Remote Session Hosts that they access helps reduce possible
        exposure of sensitive data."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000275'
  tag gid: 'V-63731'
  tag rid: 'SV-78221r1_rule'
  tag stig_id: 'WN10-CC-000275'
  tag fix_id: 'F-69659r1_fix'
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

      Value Name: fDisableCdm

      Value Type: REG_DWORD
      Value: 1"
      
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Remote Desktop Services >>
      Remote Desktop Session Host >> Device and Resource Redirection >> \"Do not
      allow drive redirection\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'fDisableCdm' }
    its('fDisableCdm') { should cmp 1 }
  end
end

