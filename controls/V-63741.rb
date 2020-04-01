# -*- encoding : utf-8 -*-

control 'V-63741' do
  title "Remote Desktop Services must be configured with the client connection
        encryption set to the required level."
  desc  "Remote connections must be encrypted to prevent interception of data
        or sensitive information. Selecting \"High Level\" will ensure encryption of
        Remote Desktop Services sessions in both directions."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000290'
  tag gid: 'V-63741'
  tag rid: 'SV-78231r1_rule'
  tag stig_id: 'WN10-CC-000290'
  tag fix_id: 'F-69669r1_fix'
  tag cci: %w[CCI-000068 CCI-002890]
  tag nist: ['AC-17 (2)', 'MA-4 (6)', 'Rev_4']
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

      Value Name: MinEncryptionLevel

      Value Type: REG_DWORD
      Value: 3"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Remote Desktop Services >>
      Remote Desktop Session Host >> Security >> \"Set client connection encryption
      level\" to \"Enabled\" and \"High Level\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'MinEncryptionLevel' }
    its('MinEncryptionLevel') { should cmp 3 }
  end
end

