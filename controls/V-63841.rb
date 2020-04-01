# -*- encoding : utf-8 -*-

control 'V-63841' do
  title 'Zone information must be preserved when saving attachments.'
  desc  "Preserving zone of origin (internet, intranet, local, restricted)
        information on file attachments allows Windows to determine risk."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UC-000020'
  tag gid: 'V-63841'
  tag rid: 'SV-78331r2_rule'
  tag stig_id: 'WN10-UC-000020'
  tag fix_id: 'F-78717r1_fix'
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
  desc "check", "The default behavior is for Windows to mark file attachments with
      their zone information.

      If the registry Value Name below does not exist, this is not a finding.

      If it exists and is configured with a value of \"2\", this is not a finding.

      If it exists and is configured with a value of \"1\", this is a finding.

      Registry Hive: HKEY_CURRENT_USER
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments\\

      Value Name: SaveZoneInformation

      Value Type: REG_DWORD
      Value: 0x00000002 (2) (or if the Value Name does not exist)"
  desc "fix", "The default behavior is for Windows to mark file attachments with
      their zone information.

      If this needs to be corrected, configure the policy value for User
      Configuration >> Administrative Templates >> Windows Components >> Attachment
      Manager >> \"Do not preserve zone information in file attachments\" to \"Not
      Configured\" or \"Disabled\"."

  describe.one do
    describe registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments') do
      it { should have_property 'SaveZoneInformation' }
      its('SaveZoneInformation') { should_not be 1 }
    end
    describe registry_key('HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments') do
      it { should_not have_property 'SaveZoneInformation' }
    end
  end
end

