# -*- encoding : utf-8 -*-

control 'V-71765' do
  title 'Internet connection sharing must be disabled.'
  desc  "Internet connection sharing makes it possible for an existing internet
        connection, such as through wireless, to be shared and used by other systems
        essentially creating a mobile hotspot.  This exposes the system sharing the
        connection to others with potentially malicious purpose."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000044'
  tag gid: 'V-71765'
  tag rid: 'SV-86389r1_rule'
  tag stig_id: 'WN10-CC-000044'
  tag fix_id: 'F-78117r2_fix'
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
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Network Connections\\

      Value Name: NC_ShowSharedAccessUI

      Type: REG_DWORD
      Value: 0x00000000 (0)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Network >> Network Connections >> \"Prohibit use of
      Internet Connection Sharing on your DNS domain network\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections') do
    it { should have_property 'NC_ShowSharedAccessUI' }
    its('NC_ShowSharedAccessUI') { should cmp 0 }
  end
end

