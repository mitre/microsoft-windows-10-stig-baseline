control "V-94859" do
  title "Windows 10 systems must use a BitLocker PIN for pre-boot
authentication."
  desc  "If data at rest is unencrypted, it is vulnerable to disclosure. Even
if the operating system enforces permissions on data access, an adversary can
remove non-volatile memory and read it directly, thereby circumventing
operating system controls. Encrypting the data ensures that confidentiality is
protected even when the operating system is not running. Pre-boot
authentication prevents unauthorized users from accessing encrypted drives."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-00-000031"
  tag gid: "V-94859"
  tag rid: "SV-104689r1_rule"
  tag stig_id: "WN10-00-000031"
  tag fix_id: "F-100983r2_fix"
  tag cci: ["CCI-001199", "CCI-002475", "CCI-002476"]
  tag nist: ["SC-28", "SC-28 (1)", "SC-28 (1)", "Rev_4"]
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
  tag check: "If the following registry value does not exist or is not
configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\FVE\\

Value Name: UseAdvancedStartup
Type: REG_DWORD
Value: 0x00000001 (1)

If one of the following registry values does not exist or is not configured as
specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\FVE\\

Value Name: UseTPMPIN
Type: REG_DWORD
Value: 0x00000001 (1)

Value Name: UseTPMKeyPIN
Type: REG_DWORD
Value: 0x00000001 (1)


BitLocker network unlock may be used in conjunction with a BitLocker PIN. See
the article below regarding information about network unlock.

https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-how-to-enable-network-unlock"
  tag fix: "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> BitLocker Drive Encryption >>
Operating System Drives \"Require additional authentication at startup\" to
\"Enabled\" with \"Configure TPM Startup PIN:\" set to \"Require startup PIN
with TPM\" or with \"Configure TPM startup key and PIN:\" set to \"Require
startup key and PIN with TPM\"."
end

