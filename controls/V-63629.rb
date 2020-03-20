# frozen_string_literal: true

control 'V-63629' do
  title "The network selection user interface (UI) must not be displayed on the
        logon screen."
  desc  "Enabling interaction with the network selection UI allows users to
        change connections to available networks without signing into Windows."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000120'
  tag gid: 'V-63629'
  tag rid: 'SV-78119r1_rule'
  tag stig_id: 'WN10-CC-000120'
  tag fix_id: 'F-69559r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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
      configured as specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

      Value Name: DontDisplayNetworkSelectionUI

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> Logon >> \"Do not display network
      selection UI\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
    it { should have_property 'DontDisplayNetworkSelectionUI' }
    its('DontDisplayNetworkSelectionUI') { should cmp 1 }
  end
end
