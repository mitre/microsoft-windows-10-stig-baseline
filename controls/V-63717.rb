# -*- encoding : utf-8 -*-

control 'V-63717' do
  title "The use of a hardware security device with Windows Hello for Business
        must be enabled."
  desc  "The use of a Trusted Platform Module (TPM) to store keys for Windows
        Hello for Business provides additional security.  Keys stored in the TPM may
        only be used on that system while keys stored using software are more
        susceptible to compromise and could be used on other systems."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000255'
  tag gid: 'V-63717'
  tag rid: 'SV-78207r5_rule'
  tag stig_id: 'WN10-CC-000255'
  tag fix_id: 'F-83247r2_fix'
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

  desc "check", "Virtual desktop implementations currently may not support the use
      of TPMs. For virtual desktop implementations where the virtual desktop instance
      is deleted or refreshed upon logoff, this is NA.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\PassportForWork\\

      Value Name: RequireSecurityDevice

      Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Windows Hello for Business >>
      \"Use a hardware security device\" to \"Enabled\".

      v1507 LTSB:
      The policy path is Computer Configuration >> Administrative Templates >>
      Windows Components >> Microsoft Passport for Work."

  if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-63717.' do
      skip 'This is a VDI System; This System is NA for Control V-63717.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\PassportForWork') do
      it { should have_property 'RequireSecurityDevice' }
      its('RequireSecurityDevice') { should cmp 1 }
    end
  end
end

