control "V-94861" do
  title "Windows 10 systems must use a BitLocker PIN with a minimum length of 6
digits for pre-boot authentication."
  desc  "If data at rest is unencrypted, it is vulnerable to disclosure. Even
if the operating system enforces permissions on data access, an adversary can
remove non-volatile memory and read it directly, thereby circumventing
operating system controls. Encrypting the data ensures that confidentiality is
protected even when the operating system is not running. Pre-boot
authentication prevents unauthorized users from accessing encrypted drives.
Increasing the pin length requires a greater number of guesses for an attacker."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-00-000032"
  tag gid: "V-94861"
  tag rid: "SV-104691r1_rule"
  tag stig_id: "WN10-00-000032"
  tag fix_id: "F-100985r1_fix"
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

Value Name: MinimumPIN
Type: REG_DWORD
Value: 0x00000006 (6) or greater"
  tag fix: "Configure the policy value for Computer Configuration >>
Administrative Templates >> Windows Components >> BitLocker Drive Encryption >>
Operating System Drives \"Configure minimum PIN length for startup\" to
\"Enabled\" with \"Minimum characters:\" set to \"6\" or greater."
  describe registry_key('HKEY_LOCAL_MACHINE\\SOFTWARE\Microsoft\Windows\CurrentVersion\Bitlocker') do
    it { should have_property 'MinimumPIN' }
    its('MinimumPIN') { should be >= 6 }
  end
end

