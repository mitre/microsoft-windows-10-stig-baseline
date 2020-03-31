# -*- encoding : utf-8 -*-

control 'V-63677' do
  title "Enhanced anti-spoofing for facial recognition must be enabled on
        Window 10."
  desc  "Enhanced anti-spoofing provides additional protections when using
        facial recognition with devices that support it."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000195'
  tag gid: 'V-63677'
  tag rid: 'SV-78167r3_rule'
  tag stig_id: 'WN10-CC-000195'
  tag fix_id: 'F-88435r1_fix'
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
  desc "check", "Windows 10 v1507 LTSB version does not include this setting; it
      is NA for those systems.

      If the following registry value does not exist or is not configured as
      specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Biometrics\\FacialFeatures\\

      Value Name: EnhancedAntiSpoofing

      Value Type: REG_DWORD
      Value: 0x00000001 (1)"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Biometrics >> Facial Features
      >> \"Configure enhanced anti-spoofing\" to \"Enabled\".

      v1607:
      The policy name is \"Use enhanced anti-spoofing when available\"."

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId == '1507'
    impact 0.0
    describe 'Windows 10 v1507 LTSB version does not include this setting.' do
      skip 'Windows 10 v1507 LTSB version does not include this setting.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures') do
      it { should have_property 'EnhancedAntiSpoofing' }
      its('EnhancedAntiSpoofing') { should cmp 1 }
    end
  end
end

