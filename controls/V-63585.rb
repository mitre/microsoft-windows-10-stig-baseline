# -*- encoding : utf-8 -*-

control 'V-63585' do
  title "Connections to non-domain networks when connected to a domain
        authenticated network must be blocked."
  desc  "Multiple network connections can provide additional attack vectors to
        a system and should be limited.  When connected to a domain, communication must
        go through the domain connection."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000060'
  tag gid: 'V-63585'
  tag rid: 'SV-78075r1_rule'
  tag stig_id: 'WN10-CC-000060'
  tag fix_id: 'F-69515r1_fix'
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
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

      Value Name: fBlockNonDomain

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Network >> Windows Connection Manager >> \"Prohibit
      connection to non-domain networks when connected to domain authenticated
      network\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
    it { should have_property 'fBlockNonDomain' }
    its('fBlockNonDomain') { should cmp 1 }
  end
end

