# -*- encoding : utf-8 -*-

control 'V-74723' do
  title 'The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.'
  desc  "SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB.
        MD5 is known to be vulnerable to a number of attacks such as collision and
        preimage attacks as well as not being FIPS compliant.

        Disabling SMBv1 support may prevent access to file or print sharing
        resources with systems or devices that only support SMBv1. File shares and
        print services hosted on Windows Server 2003 are an example, however Windows
        Server 2003 is no longer a supported operating system. Some older network
        attached devices may only support SMBv1."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000165'
  tag gid: 'V-74723'
  tag rid: 'SV-89397r1_rule'
  tag stig_id: 'WN10-00-000165'
  tag fix_id: 'F-81337r2_fix'
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
  desc "check", "Different methods are available to disable SMBv1 on Windows 10,
      if V-70639 is configured, this is NA.

      If the following registry value does not exist or is not configured as
      specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\

      Value Name: SMB1

      Type: REG_DWORD
      Value: 0x00000000 (0)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> MS Security Guide >> \"Configure SMBv1 Server\" to
      \"Disabled\".

      This policy setting requires the installation of the SecGuide custom templates
      included with the STIG package. \"SecGuide.admx\" and \"SecGuide.adml\" must be
      copied to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively.

      The system must be restarted for the change to take effect."

  smb1protocol = json( command: 'Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol | ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json').params
  state = smb1protocol['State']

  if state == "Disabled"
    impact 0.0
    describe 'V-70639 is configured, this control is NA' do
      skip 'V-70639 is configured, this control is NA'
    end
  elsif windows_feature('FS-SMB1').installed?
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters') do
      it { should have_property 'SMB1' }
      its('SMB1') { should cmp 0 }
    end
  else
    impact 0.0
    desc 'SMBv1 is not installed on this system, therefore this control is not applicable'
    describe 'SMBv1 is not installed on this system, therefore this control is not applicable' do
      skip 'SMBv1 is not installed on this system, therefore this control is not applicable'
    end
  end
end