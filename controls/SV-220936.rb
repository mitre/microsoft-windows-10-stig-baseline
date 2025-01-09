control 'SV-220936' do
  title 'Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.'
  desc 'Certain encryption types are no longer considered secure.  This setting configures a minimum encryption type for Kerberos, preventing the use of the DES and RC4 encryption suites.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\

Value Name: SupportedEncryptionTypes

Value Type: REG_DWORD
Value: 0x7ffffff8 (2147483640)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Configure encryption types allowed for Kerberos" to "Enabled" with only the following selected:

AES128_HMAC_SHA1
AES256_HMAC_SHA1
Future encryption types'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22651r555293_chk'
  tag severity: 'medium'
  tag gid: 'V-220936'
  tag rid: 'SV-220936r971535_rule'
  tag stig_id: 'WN10-SO-000190'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-22640r555294_fix'
  tag 'documentable'
  tag legacy: ['SV-78285', 'V-63795']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
    it { should have_property 'SupportedEncryptionTypes' }
    its('SupportedEncryptionTypes') { should cmp 2_147_483_640 }
  end
end
