control "V-63337" do
  title "Windows 10 information systems must use BitLocker to encrypt all disks
to protect the confidentiality and integrity of all information at rest."
  desc  "If data at rest is unencrypted, it is vulnerable to disclosure.  Even
if the operating system enforces permissions on data access, an adversary can
remove non-volatile memory and read it directly, thereby circumventing
operating system controls.   Encrypting the data ensures that confidentiality
is protected even when the operating system is not running."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-00-000030"
  tag gid: "V-63337"
  tag rid: "SV-77827r4_rule"
  tag stig_id: "WN10-00-000030"
  tag fix_id: "F-100987r1_fix"
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
  tag check: "Verify all Windows 10 information systems (including SIPRNET)
employ BitLocker for full disk encryption.

If full disk encryption using BitLocker is not implemented, this is a finding.

Verify BitLocker is turned on for the operating system drive and any fixed data
drives.

Open \"BitLocker Drive Encryption\" from the Control Panel.

If the operating system drive or any fixed data drives have \"Turn on
BitLocker\", this is a finding.

NOTE: An alternate encryption application may be used in lieu of BitLocker
providing it is configured for full disk encryption and satisfies the pre-boot
authentication requirements (WN10-00-000031 and WN10-00-000032)."
  tag fix: "Enable full disk encryption on all information systems (including
SIPRNET) using BitLocker.

BitLocker, included in Windows, can be enabled in the Control Panel under
\"BitLocker Drive Encryption\" as well as other management tools.

NOTE: An alternate encryption application may be used in lieu of BitLocker
providing it is configured for full disk encryption and satisfies the pre-boot
authentication requirements (WN10-00-000031 and WN10-00-000032)."
end

