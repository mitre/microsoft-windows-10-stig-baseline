# -*- encoding : utf-8 -*-

control 'V-63645' do
  title "Users must be prompted for a password on resume from sleep (on
        battery)."
  desc  "Authentication must always be required when accessing a system.  This
        setting ensures the user is prompted for a password on resume from sleep (on
        battery)."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000145'
  tag gid: 'V-63645'
  tag rid: 'SV-78135r1_rule'
  tag stig_id: 'WN10-CC-000145'
  tag fix_id: 'F-69575r1_fix'
  tag cci: ['CCI-002038']
  tag nist: %w[IA-11 Rev_4]
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
      Registry Path:
      \\SOFTWARE\\Policies\\Microsoft\\Power\\PowerSettings\\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\\

      Value Name: DCSettingIndex

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> Power Management >> Sleep Settings >>
      \"Require a password when a computer wakes (on battery)\" to \"Enabled\"."

    if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-63645.' do
      skip 'This is a VDI System; This System is NA for Control V-63645.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51') do
     it { should have_property 'DCSettingIndex' }
     its('DCSettingIndex') { should cmp 1 }
   end
 end
end

