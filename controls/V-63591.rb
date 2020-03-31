# -*- encoding : utf-8 -*-

control 'V-63591' do
  title 'Wi-Fi Sense must be disabled.'
  desc  "Wi-Fi Sense automatically connects the system to known hotspots and
        networks that contacts have shared.  It also allows the sharing of the system's
        known networks to contacts.  Automatically connecting to hotspots and shared
        networks can expose a system to unsecured or potentially malicious systems."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000065'
  tag gid: 'V-63591'
  tag rid: 'SV-78081r2_rule'
  tag stig_id: 'WN10-CC-000065'
  tag fix_id: 'F-88431r2_fix'
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
  desc "check", "This is NA as of v1803 of Windows 10; Wi-Fi sense is no longer
      available.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config\\

      Value Name: AutoConnectAllowedOEM

      Type: REG_DWORD
      Value: 0x00000000 (0)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Network >> WLAN Service >> WLAN Settings>> \"Allow
      Windows to automatically connect to suggested open hotspots, to networks shared
      by contacts, and to hotspots offering paid services\" to \"Disabled\".

      v1507 LTSB does not include this group policy setting.  It may be configured
      through other means such as using group policy from a later version of Windows
      10 or a registry update."

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId >= '1803'
    impact 0.0
    describe 'This is NA as of v1803 of Windows 10; Wi-Fi sense is no longer available.' do
      skip 'This is NA as of v1803 of Windows 10; Wi-Fi sense is no longer available.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config') do
      it { should have_property 'AutoConnectAllowedOEM' }
      its('AutoConnectAllowedOEM') { should cmp 0 }
    end
  end
end

