# -*- encoding : utf-8 -*-

control 'V-63719' do
  title "The Windows SMB server must be configured to always perform SMB packet
        signing."
  desc  "The server message block (SMB) protocol provides the basis for many
        network operations.  Digitally signed SMB packets aid in preventing
        man-in-the-middle attacks.  If this policy is enabled, the SMB server will only
        communicate with an SMB client that performs SMB packet signing."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000120'
  tag gid: 'V-63719'
  tag rid: 'SV-78209r1_rule'
  tag stig_id: 'WN10-SO-000120'
  tag fix_id: 'F-69647r1_fix'
  tag cci: %w[CCI-002418 CCI-002421]
  tag nist: ['SC-8', 'SC-8 (1)', 'Rev_4']
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters\\

      Value Name: RequireSecuritySignature

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Microsoft network server: Digitally sign communications (always)\" to
      \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters') do
    it { should have_property 'RequireSecuritySignature' }
    its('RequireSecuritySignature') { should cmp 1 }
  end
end

