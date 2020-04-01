# -*- encoding : utf-8 -*-

control 'V-82137' do
  title "The use of personal accounts for OneDrive synchronization must be
        disabled."
  desc  "OneDrive provides access to external services for data storage, which
        must be restricted to authorized instances. Enabling this setting will prevent
        the use of personal OneDrive accounts for synchronization."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-UC-000005'
  tag gid: 'V-82137'
  tag rid: 'SV-96851r1_rule'
  tag stig_id: 'WN10-UC-000005'
  tag fix_id: 'F-88989r2_fix'
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

      Registry Hive: HKEY_CURRENT_USER
      Registry Path: \\Software\\Policies\\Microsoft\\OneDrive\\

      Value Name: DisablePersonalSync

      Value Type: REG_DWORD
      Value: 0x00000001 (1)"
  desc "fix", "Configure the policy value for User Configuration >> Administrative
      Templates >> OneDrive >> \"Prevent users from synchronizing personal OneDrive
      accounts\" to \"Enabled\".

      Group policy files for OneDrive are located on a system with OneDrive in
      \"%localappdata%\\Microsoft\\OneDrive\\BuildNumber\\adm\\\".

      Copy the OneDrive.admx and .adml files to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively."

  describe registry_key('HKEY_CURRENT_USER\Software\Policies\Microsoft\OneDrive') do
    it { should have_property 'DisablePersonalSync' }
    its('DisablePersonalSync') { should cmp 1 }
  end
end

