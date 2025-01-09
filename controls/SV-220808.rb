control 'SV-220808' do
  title 'Wi-Fi Sense must be disabled.'
  desc "Wi-Fi Sense automatically connects the system to known hotspots and networks that contacts have shared.  It also allows the sharing of the system's known networks to contacts.  Automatically connecting to hotspots and shared networks can expose a system to unsecured or potentially malicious systems."
  desc 'check', 'This is NA as of v1803 of Windows 10; Wi-Fi sense is no longer available.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\WcmSvc\\wifinetworkmanager\\config\\

Value Name: AutoConnectAllowedOEM

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> WLAN Service >> WLAN Settings>> "Allow Windows to automatically connect to suggested open hotspots, to networks shared by contacts, and to hotspots offering paid services" to "Disabled".   

v1507 LTSB does not include this group policy setting.  It may be configured through other means such as using group policy from a later version of Windows 10 or a registry update.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22523r554909_chk'
  tag severity: 'medium'
  tag gid: 'V-220808'
  tag rid: 'SV-220808r991589_rule'
  tag stig_id: 'WN10-CC-000065'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22512r554910_fix'
  tag 'documentable'
  tag legacy: ['V-63591', 'SV-78081']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

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
