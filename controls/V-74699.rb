# -*- encoding : utf-8 -*-

control 'V-74699' do
  title "Windows 10 must be configured to enable Remote host allows delegation
        of non-exportable credentials."
  desc  "An exportable version of credentials is provided to remote hosts when
        using credential delegation which exposes them to theft on the remote host.
        Restricted Admin mode or Remote Credential Guard allow delegation of
        non-exportable credentials providing additional protection of the credentials.
        Enabling this configures the host to support Restricted Admin mode or Remote
        Credential Guard."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000068'
  tag gid: 'V-74699'
  tag rid: 'SV-89373r2_rule'
  tag stig_id: 'WN10-CC-000068'
  tag fix_id: 'F-81317r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']
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
  desc "check", "This is NA for Windows 10 LTSC\\B versions 1507 and 1607.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\CredentialsDelegation\\

      Value Name: AllowProtectedCreds

      Type: REG_DWORD
      Value: 0x00000001 (1)"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> Credentials Delegation >> \"Remote host
      allows delegation of non-exportable credentials\" to \"Enabled\"."

  releaseID = registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId.to_i

  if ( releaseID == 1607 || releaseID <= 1507 )
    impact 0.0
    describe 'This STIG does not apply to Prior Versions before 1507 and 1607.' do
      skip 'This STIG does not apply to Prior Versions before 1507 and 1607.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation') do
      it { should have_property 'AllowProtectedCreds' }
      its('AllowProtectedCreds') { should cmp 1 }
    end
  end
end

