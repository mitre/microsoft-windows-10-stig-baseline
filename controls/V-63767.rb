# -*- encoding : utf-8 -*-

control 'V-63767' do
  title 'PKU2U authentication using online identities must be prevented.'
  desc  "PKU2U is a peer-to-peer authentication protocol.   This setting
        prevents online identities from authenticating to domain-joined systems.
        Authentication will be centrally managed with Windows user accounts."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000185'
  tag gid: 'V-63767'
  tag rid: 'SV-78257r1_rule'
  tag stig_id: 'WN10-SO-000185'
  tag fix_id: 'F-69695r1_fix'
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\LSA\\pku2u\\

      Value Name: AllowOnlineID

      Value Type: REG_DWORD
      Value: 0"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network security: Allow PKU2U authentication requests to this computer to use
      online identities\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA\pku2u') do
    it { should have_property 'AllowOnlineID' }
    its('AllowOnlineID') { should cmp 0 }
  end
end

