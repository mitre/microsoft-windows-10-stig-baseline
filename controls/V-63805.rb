# -*- encoding : utf-8 -*-

control 'V-63805' do
  title "The system must be configured to meet the minimum session security
        requirement for NTLM SSP based clients."
  desc  "Microsoft has implemented a variety of security support providers for
        use with RPC sessions.  All of the options must be enabled to ensure the
        maximum security level."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000215'
  tag gid: 'V-63805'
  tag rid: 'SV-78295r1_rule'
  tag stig_id: 'WN10-SO-000215'
  tag fix_id: 'F-69733r1_fix'
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
  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0\\

      Value Name: NTLMMinClientSec

      Value Type: REG_DWORD
      Value: 0x20080000 (537395200)"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network security: Minimum session security for NTLM SSP based (including
      secure RPC) clients\" to \"Require NTLMv2 session security\" and \"Require
      128-bit encryption\" (all options selected)."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0') do
    it { should have_property 'NTLMMinClientSec' }
    its('NTLMMinClientSec') { should cmp 537_395_200 }
  end
end

