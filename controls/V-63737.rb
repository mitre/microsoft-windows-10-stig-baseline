# -*- encoding : utf-8 -*-

control 'V-63737' do
  title "The Remote Desktop Session Host must require secure RPC
        communications."
  desc  "Allowing unsecure RPC communication exposes the system to man in the
        middle attacks and data disclosure attacks. A man in the middle attack occurs
        when an intruder captures packets between a client and server and modifies them
        before allowing the packets to be exchanged. Usually the attacker will modify
        the information in the packets in an attempt to cause either the client or
        server to reveal sensitive information."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000285'
  tag gid: 'V-63737'
  tag rid: 'SV-78227r1_rule'
  tag stig_id: 'WN10-CC-000285'
  tag fix_id: 'F-69665r1_fix'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)', 'Rev_4']
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

      Value Name: fEncryptRPCTraffic

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Remote Desktop Services >>
      Remote Desktop Session Host >> Security \"Require secure RPC communication\" to
      \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services') do
    it { should have_property 'fEncryptRPCTraffic' }
    its('fEncryptRPCTraffic') { should cmp 1 }
  end
end

