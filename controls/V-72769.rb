# -*- encoding : utf-8 -*-

control 'V-72769' do
  title 'The system must notify the user when a Bluetooth device attempts to connect.'
  desc  "If not configured properly, Bluetooth may allow rogue devices to
        communicate with a system. If a rogue device is paired with a system, there is
        potential for sensitive information to be compromised"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000230'
  tag gid: 'V-72769'
  tag rid: 'SV-87407r1_rule'
  tag stig_id: 'WN10-00-000230'
  tag fix_id: 'F-79179r1_fix'
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
  desc "check", "This is NA if the system does not have Bluetooth.

      Search for \"Bluetooth\".
      View Bluetooth Settings.
      Select \"More Bluetooth Options\"
      If \"Alert me when a new Bluetooth device wants to connect\" is not checked,
      this is a finding."
  desc "fix", "Configure Bluetooth to notify users if devices attempt to connect.
      View Bluetooth Settings.
      Ensure \"Alert me when a new Bluetooth device wants to connect\" is checked."

  if sys_info.manufacturer != 'VMware, Inc.'
    describe 'Configure Bluetooth to notify users if devices attempt to connect.
              View Bluetooth Settings. Ensure "Alert me when a new Bluetooth device 
              wants to connect" is checked' do
      skip 'This is NA if the system does not have Bluetooth'
    end
  else
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-72769.' do
      skip 'This is a VDI System; This System is NA for Control V-72769.'
    end
  end
end

