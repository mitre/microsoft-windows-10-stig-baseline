# -*- encoding : utf-8 -*-

control 'V-63685' do
  title 'The Windows Defender SmartScreen for Explorer must be enabled.'
  desc  "Windows Defender SmartScreen helps protect systems from programs
        downloaded from the internet that may be malicious. Enabling Windows Defender
        SmartScreen will warn or prevent users from running potentially malicious
        programs."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000210'
  tag gid: 'V-63685'
  tag rid: 'SV-78175r6_rule'
  tag stig_id: 'WN10-CC-000210'
  tag fix_id: 'F-98461r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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

  desc 'check', "This is applicable to unclassified systems, for other systems
      this is NA.

      If the following registry values do not exist or are not configured as
      specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

      Value Name: EnableSmartScreen

      Value Type: REG_DWORD
      Value: 0x00000001 (1)

      And

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

      Value Name: ShellSmartScreenLevel

      Value Type: REG_SZ
      Value: Block

      v1607 LTSB:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

      Value Name: EnableSmartScreen

      Value Type: REG_DWORD
      Value: 0x00000001 (1)

      v1507 LTSB:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

      Value Name: EnableSmartScreen

      Value Type: REG_DWORD
      Value: 0x00000002 (2)"

  desc 'fix', "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> File Explorer >> \"Configure
      Windows Defender SmartScreen\" to \"Enabled\" with \"Warn and prevent bypass\"
      selected.

      Windows 10 includes duplicate policies for this setting. It can also be
      configured under Computer Configuration >> Administrative Templates >> Windows
      Components >> Windows Defender SmartScreen >> Explorer.

      v1607 LTSB:
      Configure the policy value for Computer Configuration >> Administrative
      Templates >> Windows Components >> File Explorer >> \"Configure Windows
      SmartScreen\" to \"Enabled\". (Selection options are not available.)

      v1507 LTSB:
      Configure the policy value for Computer Configuration >> Administrative
      Templates >> Windows Components >> File Explorer >> \"Configure Windows
      SmartScreen\" to \"Enabled\" with \"Require approval from an administrator
      before running downloaded unknown software\" selected."

  if input('sensitive_system') == 'true'
    impact 0.0
    describe 'This Control is Not Applicable to sensitive systems.' do
      skip 'This Control is Not Applicable to sensitive systems.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
      it { should have_property 'ShellSmartScreenLevel' }
      its('ShellSmartScreenLevel') { should cmp 'Block' }
    end
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
        it { should have_property 'EnableSmartScreen' }
        its('EnableSmartScreen') { should cmp 1 }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
        it { should have_property 'EnableSmartScreen' }
        its('EnableSmartScreen') { should cmp 2 }
      end
    end
  end
end

