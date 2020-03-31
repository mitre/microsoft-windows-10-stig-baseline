# -*- encoding : utf-8 -*-

control 'V-63659' do
  title "The setting to allow Microsoft accounts to be optional for modern
        style apps must be enabled."
  desc  "Control of credentials and the system must be maintained within the
        enterprise.  Enabling this setting allows enterprise credentials to be used
        with modern style apps that support this, instead of Microsoft accounts."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-CC-000170'
  tag gid: 'V-63659'
  tag rid: 'SV-78149r2_rule'
  tag stig_id: 'WN10-CC-000170'
  tag fix_id: 'F-69587r1_fix'
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

  desc "check", "Windows 10 LTSC\\B versions do not support the Microsoft Store
      and modern apps; this is NA for those systems.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

      Value Name: MSAOptional

      Value Type: REG_DWORD
      Value: 0x00000001 (1)"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> App Runtime >> \"Allow
      Microsoft accounts to be optional\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'MSAOptional' }
    its('MSAOptional') { should cmp 1 }
  end
end

