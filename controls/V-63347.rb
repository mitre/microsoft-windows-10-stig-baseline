# -*- encoding : utf-8 -*-

control 'V-63347' do
  title "The Windows Remote Management (WinRM) service must not use Basic
        authentication."
  desc  "Basic authentication uses plain text passwords that could be used to
        compromise a system."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-CC-000345'
  tag gid: 'V-63347'
  tag rid: 'SV-77837r1_rule'
  tag stig_id: 'WN10-CC-000345'
  tag fix_id: 'F-69265r1_fix'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c', 'Rev_4']
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

  desc 'check', "If the following registry value does not exist or is not
        configured as specified, this is a finding:

        Registry Hive: HKEY_LOCAL_MACHINE
        Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

        Value Name: AllowBasic

        Value Type: REG_DWORD
        Value: 0"

  desc 'fix', "Configure the policy value for Computer Configuration >>
        Administrative Templates >> Windows Components >> Windows Remote Management
        (WinRM) >> WinRM Service >> \"Allow Basic authentication\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') do
    it { should have_property 'AllowBasic' }
    its('AllowBasic') { should cmp 0 }
  end
end

