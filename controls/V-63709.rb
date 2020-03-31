# -*- encoding : utf-8 -*-

control 'V-63709' do
  title 'The password manager function in the Edge browser must be disabled.'
  desc  "Passwords save locally for re-use when browsing may be subject to
        compromise.  Disabling the Edge password manager will prevent this for the
        browser."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000245'
  tag gid: 'V-63709'
  tag rid: 'SV-78199r4_rule'
  tag stig_id: 'WN10-CC-000245'
  tag fix_id: 'F-83245r1_fix'
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
  desc "check", "Windows 10 LTSC\\B versions do not include Microsoft Edge, this
      is NA for those systems.

      If the following registry value does not exist or is not configured as
      specified, this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\Main\\

      Value Name: FormSuggest Passwords

      Type: REG_SZ
      Value: no"
  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Microsoft Edge >> \"Configure
      Password Manager\" to \"Disabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main') do
    it { should have_property 'FormSuggest Passwords' }
    its('FormSuggest Passwords') { should cmp 'no' }
  end
end

