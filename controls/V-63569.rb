# -*- encoding : utf-8 -*-

control 'V-63569' do
  title 'Insecure logons to an SMB server must be disabled.'
  desc  "Insecure guest logons allow unauthenticated access to shared folders.
        Shared resources on a system must require authentication to establish proper
        access."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000040'
  tag gid: 'V-63569'
  tag rid: 'SV-78059r2_rule'
  tag stig_id: 'WN10-CC-000040'
  tag fix_id: 'F-69499r2_fix'
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
  desc "check", "Windows 10 v1507 LTSB version does not include this setting; it
      is NA for those systems.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\LanmanWorkstation\\

      Value Name: AllowInsecureGuestAuth

      Type: REG_DWORD
      Value: 0x00000000 (0)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Network >> Lanman Workstation >> \"Enable insecure
      guest logons\" to \"Disabled\"."

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId == '1507'
    impact 0.0
    describe 'This setting requires v1507 does not include this setting; it is NA for version.' do
      skip 'This setting requires v1507 does not include this setting; it is NA for version.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation') do
      it { should have_property 'AllowInsecureGuestAuth' }
      its('AllowInsecureGuestAuth') { should cmp 0 }
    end
  end
end

