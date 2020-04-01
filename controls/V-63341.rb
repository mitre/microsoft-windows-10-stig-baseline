# -*- encoding : utf-8 -*-

control 'V-63341' do
  title "The Windows Remote Management (WinRM) client must not use Digest
        authentication."
  desc  "Digest authentication is not as strong as other options and may be
        subject to man-in-the-middle attacks."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000360'
  tag gid: 'V-63341'
  tag rid: 'SV-77831r2_rule'
  tag stig_id: 'WN10-CC-000360'
  tag fix_id: 'F-69263r1_fix'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c', 'Rev_4']
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
        Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

        Value Name: AllowDigest

        Value Type: REG_DWORD
        Value: 0"

  desc "fix", "Configure the policy value for Computer Configuration >>
        Administrative Templates >> Windows Components >> Windows Remote Management
        (WinRM) >> WinRM Client >> \"Disallow Digest authentication\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client') do
    it { should have_property 'AllowDigest' }
    its('AllowDigest') { should cmp 0 }
  end
end

