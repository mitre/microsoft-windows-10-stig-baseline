# -*- encoding : utf-8 -*-

control 'V-63621' do
  title "Web publishing and online ordering wizards must be prevented from
        downloading a list of providers."
  desc  "Some features may communicate with the vendor, sending system
        information or downloading data or components for the feature.  Turning off
        this capability will prevent potentially sensitive information from being sent
        outside the enterprise and uncontrolled updates to the system.  This setting
        prevents Windows from downloading a list of providers for the Web publishing
        and online ordering wizards."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000105'
  tag gid: 'V-63621'
  tag rid: 'SV-78111r1_rule'
  tag stig_id: 'WN10-CC-000105'
  tag fix_id: 'F-69549r1_fix'
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
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\

      Value Name: NoWebServices

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> Internet Communication Management >>
      Internet Communication settings >> \"Turn off Internet download for Web
      publishing and online ordering wizards\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer') do
    it { should have_property 'NoWebServices' }
    its('NoWebServices') { should cmp 1 }
  end
end

