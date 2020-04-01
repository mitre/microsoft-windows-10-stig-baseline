# -*- encoding : utf-8 -*-
control "V-63667" do
  title "Autoplay must be turned off for non-volume devices."
  desc  "Allowing autoplay to execute may introduce malicious code to a system.
        Autoplay begins reading from a drive as soon as you insert media in the drive.
        As a result, the setup file of programs or music on audio media may start.
        This setting will disable autoplay for non-volume devices (such as Media
        Transfer Protocol (MTP) devices)."
  impact 0.7
  tag severity: "high"
  tag gtitle: "WN10-CC-000180"
  tag gid: "V-63667"
  tag rid: "SV-78157r1_rule"
  tag stig_id: "WN10-CC-000180"
  tag fix_id: "F-69595r1_fix"
  tag cci: ["CCI-001764"]
  tag nist: ["CM-7 (2)", "Rev_4"]
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
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

      Value Name: NoAutoplayfornonVolume

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> AutoPlay Policies >>
      \"Disallow Autoplay for non-volume devices\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    it { should have_property 'NoAutoplayfornonVolume' }
    its('NoAutoplayfornonVolume') { should cmp 1 }
  end
end


