# -*- encoding : utf-8 -*-

control 'V-63695' do
  title 'File Explorer shell protocol must run in protected mode.'
  desc  "The shell protocol will  limit the set of folders applications can
        open when run in protected mode.  Restricting files an application can open, to
        a limited set of folders, increases the security of Windows."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000225'
  tag gid: 'V-63695'
  tag rid: 'SV-78185r1_rule'
  tag stig_id: 'WN10-CC-000225'
  tag fix_id: 'F-69623r1_fix'
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

  desc "check", "The default behavior is for shell protected mode to be turned on
      for file explorer.

      If the registry value name below does not exist, this is not a finding.

      If it exists and is configured with a value of \"0\", this is not a finding.

      If it exists and is configured with a value of \"1\", this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

      Value Name: PreXPSP2ShellProtocolBehavior

      Value Type: REG_DWORD
      Value: 0 (or if the Value Name does not exist)"

  desc "fix", "The default behavior is for shell protected mode to be turned on
      for file explorer.

      If this needs to be corrected, configure the policy value for Computer
      Configuration >> Administrative Templates >> Windows Components >> File
      Explorer >> \"Turn off shell protocol protected mode\" to \"Not Configured\" or
      \"Disabled\"."

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
      it { should have_property 'PreXPSP2ShellProtocolBehavior' }
      its('PreXPSP2ShellProtocolBehavior') { should_not be 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
      it { should_not have_property 'PreXPSP2ShellProtocolBehavior' }
    end
  end
end

