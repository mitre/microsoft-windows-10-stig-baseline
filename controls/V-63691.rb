# -*- encoding : utf-8 -*-

control 'V-63691' do
  title "Turning off File Explorer heap termination on corruption must be
        disabled."
  desc  "Legacy plug-in applications may continue to function when a File
        Explorer session has become corrupt.  Disabling this feature will prevent this."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-CC-000220'
  tag gid: 'V-63691'
  tag rid: 'SV-78181r3_rule'
  tag stig_id: 'WN10-CC-000220'
  tag fix_id: 'F-78109r3_fix'
  tag cci: ['CCI-002385']
  tag nist: %w[SC-5 Rev_4]
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
  desc "check", "The default behavior is for File Explorer heap termination on
      corruption to be enabled.

      If the registry Value Name below does not exist, this is not a finding.

      If it exists and is configured with a value of \"0\", this is not a finding.

      If it exists and is configured with a value of \"1\", this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

      Value Name: NoHeapTerminationOnCorruption

      Value Type: REG_DWORD
      Value: 0x00000000 (0) (or if the Value Name does not exist)"
  desc "fix", "The default behavior is for File Explorer heap termination on
      corruption to be enabled.

      If this needs to be corrected, configure the policy value for Computer
      Configuration >> Administrative Templates >> Windows Components >> File
      Explorer >> \"Turn off heap termination on corruption\" to \"Not Configured\"
      or \"Disabled\"."

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should_not have_property 'NoHeapTerminationOnCorruption' }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should have_property 'NoHeapTerminationOnCorruption' }
      its('NoHeapTerminationOnCorruption') { should_not be 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
      it { should have_property 'NoHeapTerminationOnCorruption' }
      its('NoHeapTerminationOnCorruption') { should cmp 0 }
    end
  end
end

