# -*- encoding : utf-8 -*-

control 'V-63615' do
  title 'Downloading print driver packages over HTTP must be prevented.'
  desc  "Some features may communicate with the vendor, sending system
        information or downloading data or components for the feature.  Turning off
        this capability will prevent potentially sensitive information from being sent
        outside the enterprise and uncontrolled updates to the system.  This setting
        prevents the computer from downloading print driver packages over HTTP."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000100'
  tag gid: 'V-63615'
  tag rid: 'SV-78105r1_rule'
  tag stig_id: 'WN10-CC-000100'
  tag fix_id: 'F-69545r1_fix'
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
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\

      Value Name: DisableWebPnPDownload

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> System >> Internet Communication Management >>
      Internet Communication settings >> \"Turn off downloading of print drivers over
      HTTP\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    it { should have_property 'DisableWebPnPDownload' }
    its('DisableWebPnPDownload') { should cmp 1 }
  end
end

