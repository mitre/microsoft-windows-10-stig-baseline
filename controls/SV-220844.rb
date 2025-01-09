control 'SV-220844' do
  title 'The Windows Defender SmartScreen filter for Microsoft Edge must be enabled.'
  desc 'The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially malicious websites.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

Windows 10 LTSC\\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\\

Value Name: EnabledV9

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Edge >> "Configure Windows Defender SmartScreen" to "Enabled". 

Windows 10 includes duplicate policies for this setting. It can also be configured under Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft Edge.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22559r555017_chk'
  tag severity: 'medium'
  tag gid: 'V-220844'
  tag rid: 'SV-220844r991589_rule'
  tag stig_id: 'WN10-CC-000250'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22548r555018_fix'
  tag 'documentable'
  tag legacy: ['SV-78203', 'V-63713']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  elsif registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName == 'Windows 10 Enterprise 2016 LTSB' || registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName == 'Windows 10 Enterprise 2016 LTSC'
    impact 0.0
    describe 'This System is running either Windows 10 LTSB or Windows 10 LTSC, The Control is NA' do
      skip 'This System is running either Windows 10 LTSB or Windows 10 LTSC, The Control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter') do
      it { should have_property 'EnabledV9' }
      its('EnabledV9') { should cmp 1 }
    end
  end
end
