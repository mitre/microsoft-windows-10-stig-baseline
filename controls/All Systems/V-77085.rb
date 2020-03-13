control "V-77085" do
  title "Secure Boot must be enabled on Windows 10 systems."
  desc  "Secure Boot is a standard that ensures systems boot only to a trusted
operating system. Secure Boot is required to support additional security
features in Windows 10, including Virtualization Based Security and Credential
Guard. If Secure Boot is turned off, these security features will not function."
  impact 0.3
  tag severity: nil
  tag gtitle: "WN10-00-000020"
  tag gid: "V-77085"
  tag rid: "SV-91781r2_rule"
  tag stig_id: "WN10-00-000020"
  tag fix_id: "F-83783r1_fix"
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
  tag check: "Some older systems may not have UEFI firmware. This is currently
a CAT III; it will be raised in severity at a future date when broad support of
Windows 10 hardware and firmware requirements are expected to be met. Devices
that have UEFI firmware must have Secure Boot enabled.

For virtual desktop implementations (VDIs) where the virtual desktop instance
is deleted or refreshed upon logoff, this is NA.

Run \"System Information\".

Under \"System Summary\", if \"Secure Boot State\" does not display \"On\",
this is finding."
  tag fix: "Enable Secure Boot in the system firmware."

script = <<-EOH
$status = Confirm-SecureBootUEFI
write-output $status
EOH

  describe powershell(script) do
    its('strip') { should_not eq "False"}
  end
end

