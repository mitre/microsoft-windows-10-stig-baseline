# -*- encoding : utf-8 -*-

control 'V-63325' do
  title "The Windows Installer Always install with elevated privileges must be
        disabled."
  desc  "Standard user accounts must not be granted elevated privileges.
        Enabling Windows Installer to elevate privileges when installing applications
        can allow malicious persons and applications to gain full control of a system."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-CC-000315'
  tag gid: 'V-63325'
  tag rid: 'SV-77815r1_rule'
  tag stig_id: 'WN10-CC-000315'
  tag fix_id: 'F-69243r1_fix'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)', 'Rev_4']
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

  desc "check", "If the following registry value does not exist or is not
        configured as specified, this is a finding:

        Registry Hive: HKEY_LOCAL_MACHINE
        Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

        Value Name: AlwaysInstallElevated

        Value Type: REG_DWORD
        Value: 0"

  desc "fix", "Configure the policy value for Computer Configuration >>
        Administrative Templates >> Windows Components >> Windows Installer >> \"Always
        install with elevated privileges\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer') do
    it { should have_property 'AlwaysInstallElevated' }
    its('AlwaysInstallElevated') { should cmp 0 }
  end
end

