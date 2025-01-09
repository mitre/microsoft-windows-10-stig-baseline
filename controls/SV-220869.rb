control 'SV-220869' do
  title 'Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is locked.'
  desc 'Allowing Windows apps to be activated by voice from the lock screen could allow for unauthorized use. Requiring logon will ensure the apps are only used by authorized personnel.'
  desc 'check', 'This setting requires v1903 or later of Windows 10; it is NA for prior versions.  The setting is NA when the “Allow voice activation” policy is configured to disallow applications to be activated with voice for all users.
If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\

Value Name: LetAppsActivateWithVoiceAboveLock

Type: REG_DWORD
Value: 0x00000002 (2)

If the following registry value exists and is configured as specified, requirement is NA. 

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppPrivacy\\

Value Name: LetAppsActivateWithVoice

Type: REG_DWORD
Value: 0x00000002 (2)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Privacy >> "Let Windows apps activate with voice while the system is locked" to "Enabled" with “Default for all Apps:” set to “Force Deny”. 

The requirement is NA if the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App Privacy >> "Let Windows apps activate with voice" is configured to "Enabled" with “Default for all Apps:” set to “Force Deny”.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22584r555092_chk'
  tag severity: 'medium'
  tag gid: 'V-220869'
  tag rid: 'SV-220869r958400_rule'
  tag stig_id: 'WN10-CC-000365'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag fix_id: 'F-22573r555093_fix'
  tag 'documentable'
  tag legacy: ['V-94719', 'SV-104549']
  tag cci: ['CCI-000056']
  tag nist: ['AC-11 b']

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
