# -*- encoding : utf-8 -*-

control 'V-82139' do
  title "Windows 10 must be configured to prevent certificate error overrides
        in Microsoft Edge."
  desc  "Web security certificates provide an indication whether a site is
        legitimate. This policy setting prevents the user from ignoring Secure Sockets
        Layer/Transport Layer Security (SSL/TLS) certificate errors that interrupt
        browsing."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000238'
  tag gid: 'V-82139'
  tag rid: 'SV-96853r1_rule'
  tag stig_id: 'WN10-CC-000238'
  tag fix_id: 'F-88993r1_fix'
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
  desc "check", "This setting is applicable starting with v1809 of Windows 10; it
      is NA for prior versions.

      Windows 10 LTSC\\B versions do not include Microsoft Edge; this is NA for those
      systems.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Internet
      Settings\\

      Value Name: PreventCertErrorOverrides

      Type: REG_DWORD
      Value: 0x00000001 (1)"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Microsoft Edge >> \"Prevent
      certificate error overrides\" to \"Enabled\"."

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId >= '1809'
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings') do
      it { should have_property 'PreventCertErrorOverrides' }
      its('PreventCertErrorOverrides') { should cmp 1 }
    end
  else
    impact 0.0
    describe 'This setting is applicable starting with v1809 of Windows 10; it is NA for prior versions' do
      skip 'This setting is applicable starting with v1809 of Windows 10; it is NA for prior versions.'
    end
  end
end

