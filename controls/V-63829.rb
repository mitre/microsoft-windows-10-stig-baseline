# -*- encoding : utf-8 -*-

control 'V-63829' do
  title "User Account Control must run all administrators in Admin Approval
        Mode, enabling UAC."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
        elevation of privileges, including administrative accounts, unless authorized.
        This setting enables UAC."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000270'
  tag gid: 'V-63829'
  tag rid: 'SV-78319r1_rule'
  tag stig_id: 'WN10-SO-000270'
  tag fix_id: 'F-69757r1_fix'
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
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

      Value Name: EnableLUA

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"User
      Account Control: Run all administrators in Admin Approval Mode\" to
      \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'EnableLUAs' }
    its('EnableLUAs') { should cmp 1 }
  end
end

