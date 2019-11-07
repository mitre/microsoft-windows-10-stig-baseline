control "V-77231" do
  title "Exploit Protection mitigations in Windows 10 must be configured for
MSACCESS.EXE."
  desc  "Exploit protection in Windows 10 provides a means of enabling
additional mitigations against potential threats at the system and application
level. Without these additional application protections, Windows 10 may be
subject to various exploits."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-EP-000180"
  tag gid: "V-77231"
  tag rid: "SV-91927r3_rule"
  tag stig_id: "WN10-EP-000180"
  tag fix_id: "F-84359r4_fix"
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
  tag check: "This is NA prior to v1709 of Windows 10.

This is applicable to unclassified systems, for other systems this is NA.

Run \"Windows PowerShell\" with elevated privileges (run as administrator).

Enter \"Get-ProcessMitigation -Name MSACCESS.EXE\".
(Get-ProcessMitigation can be run without the -Name parameter to get a list of
all application mitigations configured.)

If the following mitigations do not have a status of \"ON\", this is a finding:

DEP:
Enable: ON

ASLR:
ForceRelocateImages: ON

Payload:
EnableExportAddressFilter: ON
EnableExportAddressFilterPlus: ON
EnableImportAddressFilter: ON
EnableRopStackPivot: ON
EnableRopCallerCheck: ON
EnableRopSimExec: ON

The PowerShell command produces a list of mitigations; only those with a
required status of \"ON\" are listed here. If the PowerShell command does not
produce results, ensure the letter case of the filename within the command
syntax matches the letter case of the actual filename on the system."
  tag fix: "Ensure the following mitigations are turned \"ON\" for MSACCESS.EXE:

DEP:
Enable: ON

ASLR:
ForceRelocateImages: ON

Payload:
EnableExportAddressFilter: ON
EnableExportAddressFilterPlus: ON
EnableImportAddressFilter: ON
EnableRopStackPivot: ON
EnableRopCallerCheck: ON
EnableRopSimExec: ON

Application mitigations defined in the STIG are configured by a DoD EP XML file
included with the Windows 10 STIG package in the \"Supporting Files\" folder.

The XML file is applied with the group policy setting Computer Configuration >>
Administrative Settings >> Windows Components >> Windows Defender Exploit Guard
>> Exploit Protection >> \"Use a common set of exploit protection settings\"
configured to \"Enabled\" with file name and location defined under
\"Options:\".  It is recommended the file be in a read-only network location."
end

