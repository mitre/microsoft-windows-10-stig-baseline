# -*- encoding : utf-8 -*-

control 'V-63819' do
  title "User Account Control must, at minimum, prompt administrators for
        consent on the secure desktop."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
        elevation of privileges, including administrative accounts, unless authorized.
        This setting configures the elevation requirements for logged on administrators
        to complete a task that requires raised privileges."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000250'
  tag gid: 'V-63819'
  tag rid: 'SV-78309r1_rule'
  tag stig_id: 'WN10-SO-000250'
  tag fix_id: 'F-69747r1_fix'
  tag cci: ['CCI-001084']
  tag nist: %w[SC-3 Rev_4]
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

      Value Name: ConsentPromptBehaviorAdmin

      Value Type: REG_DWORD
      Value: 2 (Prompt for consent on the secure desktop)"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"User
      Account Control: Behavior of the elevation prompt for administrators in Admin
      Approval Mode\" to \"Prompt for consent on the secure desktop\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'ConsentPromptBehaviorAdmin' }
    its('ConsentPromptBehaviorAdmin') { should cmp 2 }
  end
end

