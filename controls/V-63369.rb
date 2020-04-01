# -*- encoding : utf-8 -*-

control 'V-63369' do
  title "The Windows Remote Management (WinRM) service must not allow
        unencrypted traffic."
  desc  "Unencrypted remote access to a system can allow sensitive information
        to be compromised.  Windows remote management connections must be encrypted to
        prevent this."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000350'
  tag gid: 'V-63369'
  tag rid: 'SV-77859r1_rule'
  tag stig_id: 'WN10-CC-000350'
  tag fix_id: 'F-69289r1_fix'
  tag cci: %w[CCI-002890 CCI-003123]
  tag nist: ['MA-4 (6)', 'MA-4 (6)', 'Rev_4']
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
        Value Name: AllowUnencryptedTraffic
        Value Type: REG_DWORD
        Value: 0"

  desc "fix", "Configure the policy value for Computer Configuration >>
        Administrative Templates >> Windows Components >> Windows Remote Management
        (WinRM) >> WinRM Service >> \"Allow unencrypted traffic\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service') do
    it { should have_property 'AllowUnencryptedTraffic' }
    its('AllowUnencryptedTraffic') { should cmp 0 }
  end
end

