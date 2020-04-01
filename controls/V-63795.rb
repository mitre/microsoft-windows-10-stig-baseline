# -*- encoding : utf-8 -*-

control 'V-63795' do
  title "Kerberos encryption types must be configured to prevent the use of DES
        and RC4 encryption suites."
  desc  "Certain encryption types are no longer considered secure.  This
        setting configures a minimum encryption type for Kerberos, preventing the use
        of the DES and RC4 encryption suites."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000190'
  tag gid: 'V-63795'
  tag rid: 'SV-78285r1_rule'
  tag stig_id: 'WN10-SO-000190'
  tag fix_id: 'F-69723r2_fix'
  tag cci: ['CCI-000803']
  tag nist: %w[IA-7 Rev_4]
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
  desc 'check', "If the following registry value does not exist or is not
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\

      Value Name: SupportedEncryptionTypes

      Value Type: REG_DWORD
      Value: 0x7ffffff8 (2147483640)"
  desc 'fix', "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Network security: Configure encryption types allowed for Kerberos\" to
      \"Enabled\" with only the following selected:

      AES128_HMAC_SHA1
      AES256_HMAC_SHA1
      Future encryption types"

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters') do
    it { should have_property 'SupportedEncryptionTypes' }
    its('SupportedEncryptionTypes') { should cmp 2_147_483_640 }
  end
end

