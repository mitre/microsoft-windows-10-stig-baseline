# -*- encoding : utf-8 -*-

control 'V-63711' do
  title 'Unencrypted passwords must not be sent to third-party SMB Servers.'
  desc  "Some non-Microsoft SMB servers only support unencrypted (plain text)
        password authentication.  Sending plain text passwords across the network, when
        authenticating to an SMB server, reduces the overall security of the
        environment.  Check with the vendor of the SMB server to see if there is a way
        to support encrypted password authentication."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000110'
  tag gid: 'V-63711'
  tag rid: 'SV-78201r1_rule'
  tag stig_id: 'WN10-SO-000110'
  tag fix_id: 'F-69639r1_fix'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)', 'Rev_4']
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

      Registry Hive:  HKEY_LOCAL_MACHINE
      Registry Path:
      \\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\

      Value Name:  EnablePlainTextPassword

      Value Type:  REG_DWORD
      Value:  0"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Microsoft network client: Send unencrypted password to third-party SMB
      servers\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters') do
    it { should have_property 'EnablePlainTextPassword' }
    its('EnablePlainTextPassword') { should cmp 0 }
  end
end

