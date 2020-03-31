# -*- encoding : utf-8 -*-

control 'V-72767' do
  title 'Bluetooth must be turned off when not in use.'
  desc  "If not configured properly, Bluetooth may allow rogue devices to
        communicate with a system. If a rogue device is paired with a system, there is
        potential for sensitive information to be compromised."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000220'
  tag gid: 'V-72767'
  tag rid: 'SV-87405r1_rule'
  tag stig_id: 'WN10-00-000220'
  tag fix_id: 'F-79177r1_fix'
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
  desc "check", "This is NA if the system does not have Bluetooth.

      Verify the organization has a policy to turn off Bluetooth when not in use and
      personnel are trained. If it does not, this is a finding."
  desc "fix", "Turn off Bluetooth radios when not in use. Establish an
      organizational policy for the use of Bluetooth to include training of
      personnel."

  if sys_info.manufacturer != 'VMware, Inc.'
    describe 'Turn off Bluetooth radios when not in use. Establish an organizational policy for the use of Bluetooth to include training of personnel' do
      skip 'This is NA if the system does not have Bluetooth'
    end
  else
    impact 0.0
    describe 'This is a VDI System; This Control is NA.' do
      skip 'This is a VDI System; This Control is NA'
    end
  end
end

