# -*- encoding : utf-8 -*-

control 'V-63801' do
  title "The LanMan authentication level must be set to send NTLMv2 response
        only, and to refuse LM and NTLM."
  desc  "The Kerberos v5 authentication protocol is the default for
        authentication of users who are logging on to domain accounts.  NTLM, which is
        less secure, is retained in later Windows versions  for compatibility with
        clients and servers that are running earlier versions of Windows or
        applications that still use it.  It is also used to authenticate logons to
        stand-alone computers that are running later versions."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-SO-000205'
  tag gid: 'V-63801'
  tag rid: 'SV-78291r1_rule'
  tag stig_id: 'WN10-SO-000205'
  tag fix_id: 'F-69729r1_fix'
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

      Value Name: LmCompatibilityLevel

      Value Type: REG_DWORD
      Value: 5"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network security: LAN Manager authentication level\" to \"Send NTLMv2
      response only. Refuse LM & NTLM\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
    it { should have_property 'LmCompatibilityLevel' }
    its('LmCompatibilityLevel') { should cmp 5 }
  end
end

