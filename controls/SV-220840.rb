control 'SV-220840' do
  title 'Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge.'
  desc 'The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially malicious websites and file downloads.  If users are allowed to ignore warnings from the Windows Defender SmartScreen filter they could still access malicious websites.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

Windows 10 LTSC\\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\\

Value Name: PreventOverride

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Edge >> "Prevent bypassing Windows Defender SmartScreen prompts for sites" to "Enabled". 

Windows 10 includes duplicate policies for this setting. It can also be configured under Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft Edge.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22555r555005_chk'
  tag severity: 'medium'
  tag gid: 'V-220840'
  tag rid: 'SV-220840r991589_rule'
  tag stig_id: 'WN10-CC-000230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22544r555006_fix'
  tag 'documentable'
  tag legacy: ['V-63699', 'SV-78189']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter') do
      it { should have_property 'PreventOverride' }
      its('PreventOverride') { should cmp 1 }
    end
  end
end
