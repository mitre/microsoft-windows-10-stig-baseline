# -*- encoding : utf-8 -*-

control 'V-63671' do
  title "The default autorun behavior must be configured to prevent autorun
        commands."
  desc  "Allowing autorun commands to execute may introduce malicious code to a
        system.  Configuring this setting prevents autorun commands from executing."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-CC-000185'
  tag gid: 'V-63671'
  tag rid: 'SV-78161r1_rule'
  tag stig_id: 'WN10-CC-000185'
  tag fix_id: 'F-69599r1_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)', 'Rev_4']
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
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

      Value Name: NoAutorun

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> AutoPlay Policies >> \"Set
      the default behavior for AutoRun\" to \"Enabled:Do not execute any autorun
      commands\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    it { should have_property 'NoAutorun' }
    its('NoAutorun') { should cmp 1 }
  end
end

