# -*- encoding : utf-8 -*-

control 'V-94719' do
  title "Windows 10 must be configured to prevent Windows apps from being
        activated by voice while the system is locked."
  desc  "Allowing Windows apps to be activated by voice from the lock screen
        could allow for unauthorized use. Requiring logon will ensure the apps are only
        used by authorized personnel."

  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000365'
  tag gid: 'V-94719'
  tag rid: 'SV-104549r1_rule'
  tag stig_id: 'WN10-CC-000365'
  tag fix_id: 'F-100837r3_fix'
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b', 'Rev_4']
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
  desc "check", "This setting requires v1903 or later of Windows 10; it is NA for
      prior versions.  The setting is NA when the “Allow voice activation” policy is
      configured to disallow applications to be activated with voice for all users.
      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\

      Value Name: LetAppsActivateWithVoiceAboveLock

      Type: REG_DWORD
      Value: 0x00000002 (2)

      If the following registry value exists and is configured as specified,
      requirement is NA.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\

      Value Name: LetAppsActivateWithVoice

      Type: REG_DWORD
      Value: 0x00000002 (2)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> App Privacy >> \"Let Windows
      apps activate with voice while the system is locked\" to \"Enabled\" with
      “Default for all Apps:” set to “Force Deny”.

      The requirement is NA if the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> App Privacy >> \"Let Windows
      apps activate with voice\" is configured to \"Enabled\" with “Default for all
      Apps:” set to “Force Deny”."

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId >= '1903'
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy') do
        it { should have_property 'LetAppsActivateWithVoiceAboveLock' }
        its('LetAppsActivateWithVoiceAboveLock') { should cmp 2 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy') do
        it { should have_property 'LetAppsActivateWithVoice' }
        its('LetAppsActivateWithVoice') { should cmp 2 }
      end
    end
  else
    impact 0.0
    describe 'This setting requires v1903 or later of Windows 10; it is NA for prior versions.' do
      skip 'This setting requires v1903 or later of Windows 10; it is NA for prior versions.'
    end
  end
end

