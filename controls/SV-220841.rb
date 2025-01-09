control 'SV-220841' do
  title 'Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge.'
  desc 'The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially malicious websites and file downloads.  If users are allowed to ignore warnings from the Windows Defender SmartScreen filter they could still download potentially malicious files.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

Windows 10 LTSC\\B versions do not include Microsoft Edge, this is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\\

Value Name: PreventOverrideAppRepUnknown

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft Edge >> "Prevent bypassing Windows Defender SmartScreen prompts for files" to "Enabled". 

Windows 10 includes duplicate policies for this setting. It can also be configured under Computer Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft Edge.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22556r555008_chk'
  tag severity: 'medium'
  tag gid: 'V-220841'
  tag rid: 'SV-220841r991589_rule'
  tag stig_id: 'WN10-CC-000235'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22545r555009_fix'
  tag 'documentable'
  tag legacy: ['SV-78191', 'V-63701']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter') do
      it { should have_property 'PreventOverrideAppRepUnknown' }
      its('PreventOverrideAppRepUnknown') { should cmp 1 }
    end
  end
end
