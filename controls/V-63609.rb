# -*- encoding : utf-8 -*-

control 'V-63609' do
  title "Group Policy objects must be reprocessed even if they have not
        changed."
  desc  "Enabling this setting and then selecting the \"Process even if the
        Group Policy objects have not changed\" option ensures that the policies will
        be reprocessed even if none have been changed. This way, any unauthorized
        changes are forced to match the domain-based group policy settings again."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000090'
  tag gid: 'V-63609'
  tag rid: 'SV-78099r1_rule'
  tag stig_id: 'WN10-CC-000090'
  tag fix_id: 'F-69539r1_fix'
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
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Group
      Policy\\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}

      Value Name: NoGPOListChanges

      Value Type: REG_DWORD
      Value: 0"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> Group Policy >> \"Configure registry
      policy processing\" to \"Enabled\" and select the option \"Process even if the
      Group Policy objects have not changed\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}') do
    it { should have_property 'NoGPOListChanges' }
    its('NoGPOListChanges') { should cmp 0 }
  end
end

