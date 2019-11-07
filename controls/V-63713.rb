control "V-63713" do
  title "The Windows Defender SmartScreen filter for Microsoft Edge must be
enabled."
  desc  "The Windows Defender SmartScreen filter in Microsoft Edge provides
warning messages and blocks potentially malicious websites."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-CC-000250"
  tag gid: "V-63713"
  tag rid: "SV-78203r6_rule"
  tag stig_id: "WN10-CC-000250"
  tag fix_id: "F-98467r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]
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
  tag check: "This is applicable to unclassified systems, for other systems
this is NA.

Windows 10 LTSC\\B versions do not include Microsoft Edge, this is NA for those
systems.

If the following registry value does not exist or is not configured as
specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter\\

Value Name: EnabledV9

Type: REG_DWORD
Value: 0x00000001 (1)"
  tag fix: "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> Microsoft Edge >> \"Configure
Windows Defender SmartScreen\" to \"Enabled\".

Windows 10 includes duplicate policies for this setting. It can also be
configured under Computer Configuration >> Administrative Templates >> Windows
Components >> Windows Defender SmartScreen >> Microsoft Edge."
end

