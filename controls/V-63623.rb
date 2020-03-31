# -*- encoding : utf-8 -*-

control 'V-63623' do
  title 'Printing over HTTP must be prevented.'
  desc  "Some features may communicate with the vendor, sending system
        information or downloading data or components for the feature.  Turning off
        this capability will prevent potentially sensitive information from being sent
        outside the enterprise and uncontrolled updates to the system.  This setting
        prevents the client computer from printing over HTTP, which allows the computer
        to print to printers on the intranet as well as the Internet."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000110'
  tag gid: 'V-63623'
  tag rid: 'SV-78113r1_rule'
  tag stig_id: 'WN10-CC-000110'
  tag fix_id: 'F-69553r1_fix'
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

      Value Name: DisableHTTPPrinting

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
Administrative Templates >> System >> Internet Communication Management >>
Internet Communication settings >> \"Turn off printing over HTTP\" to
\"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers') do
    it { should have_property 'DisableHTTPPrinting' }
    its('DisableHTTPPrinting') { should cmp 1 }
  end
end

