# -*- encoding : utf-8 -*-

control 'V-63375' do
  title "The Windows Remote Management (WinRM) service must not store RunAs
        credentials."
  desc  "Storage of administrative credentials could allow unauthorized access.
        Disallowing the storage of RunAs credentials for Windows Remote Management
        will prevent them from being used with plug-ins."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000355'
  tag gid: 'V-63375'
  tag rid: 'SV-77865r1_rule'
  tag stig_id: 'WN10-CC-000355'
  tag fix_id: 'F-69293r1_fix'
  tag cci: ['CCI-002038']
  tag nist: %w[IA-11 Rev_4]
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
        Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\
        Value Name: DisableRunAs
        Value Type: REG_DWORD
        Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
        Administrative Templates >> Windows Components >> Windows Remote Management
        (WinRM) >> WinRM Service >> \"Disallow WinRM from storing RunAs credentials\"
        to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') do
    it { should have_property 'DisableRunAs' }
    its('DisableRunAs') { should cmp 1 }
  end
end

