# -*- encoding : utf-8 -*-
control "V-72765" do
  title "Bluetooth must be turned off unless approved by the organization."
  desc  "If not configured properly, Bluetooth may allow rogue devices to
        communicate with a system. If a rogue device is paired with a system, there is
        potential for sensitive information to be compromised."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "WN10-00-000210"
  tag gid: "V-72765"
  tag rid: "SV-87403r1_rule"
  tag stig_id: "WN10-00-000210"
  tag fix_id: "F-79175r1_fix"
  tag cci: ["CCI-000381"]
  tag nist: ["CM-7 a", "Rev_4"]
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

      Verify the Bluetooth radio is turned off unless approved by the organization.
      If it is not, this is a finding.

      Approval must be documented with the ISSO."
  desc "fix", "Turn off Bluetooth radios not organizationally approved. Establish
    an organizational policy for the use of Bluetooth."

if(sys_info).manufacturer != "VMware, Inc."
  describe "Turn off Bluetooth radios when not in use. Establish an organizational policy for the use of Bluetooth to include training of personnel" do
    skip 'This is NA if the system does not have Bluetooth'
  end
else
  impact 0.0
  describe "This is a VDI System this control is NA." do
    skip 'This is a VDI System this control is NA.'
   end
  end
end


