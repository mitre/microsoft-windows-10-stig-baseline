# -*- encoding : utf-8 -*-
control "V-71771" do
  title "Microsoft consumer experiences must be turned off."
  desc  "Microsoft consumer experiences provides suggestions and notifications
        to users, which may include the installation of Windows Store apps.
        Organizations may control the execution of applications through other means
        such as whitelisting.  Turning off Microsoft consumer experiences will help
        prevent the unwanted installation of suggested applications."
  impact 0.3
  tag severity: "low"
  tag gtitle: "WN10-CC-000197"
  tag gid: "V-71771"
  tag rid: "SV-86395r2_rule"
  tag stig_id: "WN10-CC-000197"
  tag fix_id: "F-78123r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]
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
  desc "check", "Windows 10 v1507 LTSB version does not include this setting; it
      is NA for those systems.

      If the following registry value does not exist or is not configured as
      specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent\\

      Value Name: DisableWindowsConsumerFeatures

      Type: REG_DWORD
      Value: 0x00000001 (1)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Cloud Content >> \"Turn off
      Microsoft consumer experiences\" to \"Enabled\"."

if (registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId != "1507" )
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent') do
    it { should have_property 'DisableWindowsConsumerFeatures' }
    its('DisableWindowsConsumerFeatures') { should cmp 1 } 
  end
else 
  impact 0.0
  describe "Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems." do
    skip 'Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.'
  end 
 end
end


