# encoding: UTF-8

control "V-99557" do
  title "Windows 10 Kernel (Direct Memory Access) DMA Protection must be
enabled."
  desc  "Kernel DMA Protection to protect PCs against drive-by Direct Memory
Access (DMA) attacks using PCI hot plug devices connected to Thunderbolt™ 3
ports. Drive-by DMA attacks can lead to disclosure of sensitive information
residing on a PC, or even injection of malware that allows attackers to bypass
the lock screen or control PCs remotely."
  desc  "rationale", ""
  desc  "check", "
    This is NA prior to v1803 of Windows 10.

    If the following registry value does not exist or is not configured as
specified, this is a finding.

    Registry Hive: HKEY_LOCAL_MACHINE
    Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Kernel DMA
Protection

    Value Name: DeviceEnumerationPolicy
    Value Type: REG_DWORD
    Value: 0
  "
  desc  "fix", "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Kernel DMA Protection >> \"Enumeration
policy for external devices incompatible with Kernel DMA Protection\" to
\"Enabled\" with \"Enumeration Policy\" set to \"Block All\"."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-EP-000310"
  tag gid: "V-99557"
  tag rid: "SV-108661r1_rule"
  tag stig_id: "WN10-EP-000310"
  tag fix_id: "F-105241r4_fix"
  tag cci: ["CCI-001090"]
  tag nist: ["SC-4", "Rev_4"]
end

