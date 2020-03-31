# -*- encoding : utf-8 -*-

control 'V-63673' do
  title 'Autoplay must be disabled for all drives.'
  desc  "Allowing autoplay to execute may introduce malicious code to a system.
        Autoplay begins reading from a drive as soon as you insert media in the drive.
        As a result, the setup file of programs or music on audio media may start.  By
        default, autoplay is disabled on removable drives, such as the floppy disk
        drive (but not the CD-ROM drive) and on network drives.  If you enable this
        policy, you can also disable autoplay on all drives."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-CC-000190'
  tag gid: 'V-63673'
  tag rid: 'SV-78163r1_rule'
  tag stig_id: 'WN10-CC-000190'
  tag fix_id: 'F-69603r1_fix'
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
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\Explorer\\

      Value Name: NoDriveTypeAutoRun

      Value Type: REG_DWORD
      Value: 0x000000ff (255)

      Note: If the value for NoDriveTypeAutorun is entered manually, it must be
      entered as \"ff\" when Hexadecimal is selected, or \"255\" with Decimal
      selected.  Using the policy value specified in the Fix section will enter it
      correctly."
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> AutoPlay Policies >> \"Turn
      off AutoPlay\" to \"Enabled:All Drives\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer') do
    it { should have_property 'NoDriveTypeAutoRun' }
    its('NoDriveTypeAutoRun') { should cmp 255 }
  end
end

