# -*- encoding : utf-8 -*-

control 'V-63751' do
  title 'Indexing of encrypted files must be turned off.'
  desc  "Indexing of encrypted files may expose sensitive data.  This setting
        prevents encrypted files from being indexed."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000305'
  tag gid: 'V-63751'
  tag rid: 'SV-78241r1_rule'
  tag stig_id: 'WN10-CC-000305'
  tag fix_id: 'F-69679r1_fix'
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
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search\\

      Value Name: AllowIndexingEncryptedStoresOrItems

      Value Type: REG_DWORD
      Value: 0"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Search >> \"Allow indexing of
      encrypted files\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search') do
    it { should have_property 'AllowIndexingEncryptedStoresOrItems' }
    its('AllowIndexingEncryptedStoresOrItems') { should cmp 0 }
  end
end

