# -*- encoding : utf-8 -*-

control 'V-71763' do
  title 'WDigest Authentication must be disabled.'
  desc  "When the WDigest Authentication protocol is enabled, plain text
        passwords are stored in the Local Security Authority Subsystem Service (LSASS)
        exposing them to theft.  WDigest is disabled by default in Windows 10.  This
        setting ensures this is enforced."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000038'
  tag gid: 'V-71763'
  tag rid: 'SV-86387r1_rule'
  tag stig_id: 'WN10-CC-000038'
  tag fix_id: 'F-78115r4_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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
      configured as specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Wdigest\\

      Value Name: UseLogonCredential

      Type: REG_DWORD
      Value:  0x00000000 (0)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> MS Security Guide >> \"WDigest Authentication
      (disabling may require KB2871997)\" to \"Disabled\".

      The patch referenced in the policy title is not required for Windows 10.

      This policy setting requires the installation of the SecGuide custom templates
      included with the STIG package.  \"SecGuide.admx\" and \"SecGuide.adml\" must
      be copied to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest') do
    it { should have_property 'UseLogonCredential' }
    its('UseLogonCredential') { should cmp 0 }
  end
end

