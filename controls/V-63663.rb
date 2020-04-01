# -*- encoding : utf-8 -*-

control 'V-63663' do
  title "The Application Compatibility Program Inventory must be prevented from
        collecting data and sending the information to Microsoft."
  desc  "Some features may communicate with the vendor, sending system
        information or downloading data or components for the feature.  Turning off
        this capability will prevent potentially sensitive information from being sent
        outside the enterprise and uncontrolled updates to the system.  This setting
        will prevent the Program Inventory from collecting data about a system and
        sending the information to Microsoft."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-CC-000175'
  tag gid: 'V-63663'
  tag rid: 'SV-78153r1_rule'
  tag stig_id: 'WN10-CC-000175'
  tag fix_id: 'F-69591r1_fix'
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
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\AppCompat\\

      Value Name: DisableInventory

      Value Type: REG_DWORD
      Value: 1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> Windows Components >> Application Compatibility >>
      \"Turn off Inventory Collector\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat') do
    it { should have_property 'DisableInventory' }
    its('DisableInventory') { should cmp 1 }
  end
end

