# -*- encoding : utf-8 -*-

control 'V-63657' do
  title "Unauthenticated RPC clients must be restricted from connecting to the
        RPC server."
  desc  "Configuring RPC to restrict unauthenticated RPC clients from
        connecting to the RPC server will prevent anonymous connections."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000165'
  tag gid: 'V-63657'
  tag rid: 'SV-78147r1_rule'
  tag stig_id: 'WN10-CC-000165'
  tag fix_id: 'F-69585r1_fix'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)', 'Rev_4']
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
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Rpc\\

      Value Name: RestrictRemoteClients

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> Remote Procedure Call >> \"Restrict
      Unauthenticated RPC clients\" to \"Enabled\" and \"Authenticated\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Rpc') do
    it { should have_property 'RestrictRemoteClients' }
    its('RestrictRemoteClients') { should cmp 1 }
  end
end

