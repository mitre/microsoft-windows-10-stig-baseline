control "V-68849" do
  title "Structured Exception Handling Overwrite Protection (SEHOP) must be
enabled."
  desc  "Attackers are constantly looking for vulnerabilities in systems and
applications. Structured Exception Handling Overwrite Protection (SEHOP) blocks
exploits that use the Structured Exception Handling overwrite technique, a
common buffer overflow attack."
  impact 0.7
  tag severity: nil
  tag gtitle: "WN10-00-000150"
  tag gid: "V-68849"
  tag rid: "SV-83445r4_rule"
  tag stig_id: "WN10-00-000150"
  tag fix_id: "F-87295r1_fix"
  tag cci: ["CCI-002824"]
  tag nist: ["SI-16", "Rev_4"]
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
  tag check: "This is applicable to Windows 10 prior to v1709.

Verify SEHOP is turned on.

If the following registry value does not exist or is not configured as
specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\\

Value Name: DisableExceptionChainValidation

Value Type: REG_DWORD
Value: 0x00000000 (0)"
  tag fix: "Configure the policy value for Computer Configuration >>
Administrative Templates >> MS Security Guide >> \"Enable Structured Exception
Handling Overwrite Protection (SEHOP)\" to \"Enabled\".

This policy setting requires the installation of the SecGuide custom templates
included with the STIG package. \"SecGuide.admx\" and \"SecGuide.adml\" must be
copied to the \\Windows\\PolicyDefinitions and
\\Windows\\PolicyDefinitions\\en-US directories respectively."
  describe registry_key('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel') do
    it { should have_property 'DisableExceptionChainValidation'}
    its('DisableExceptionChainValidation') { should cmp 0 }
  end
end

