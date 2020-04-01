# -*- encoding : utf-8 -*-

control 'V-63355' do
  title 'Alternate operating systems must not be permitted on the same system.'
  desc  "Allowing other operating systems to run on a secure system may allow
        security to be circumvented."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000055'
  tag gid: 'V-63355'
  tag rid: 'SV-77845r1_rule'
  tag stig_id: 'WN10-00-000055'
  tag fix_id: 'F-69275r1_fix'
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
  desc "check", "Verify the system does not include other operating system
        installations.

        Run \"Advanced System Settings\".
        Select the \"Advanced\" tab.
        Click the \"Settings\" button in the \"Startup and Recovery\" section.

        If the drop-down list box \"Default operating system:\" shows any operating
        system other than Windows 10, this is a finding."

  desc "fix", "Ensure Windows 10 is the only operating system on a device.  Remove
        alternate operating systems."

  describe command("bcdedit | Findstr description | Findstr /v /c:'Windows Boot Manager'") do
    its('stdout') { should eq "description             Windows 10\r\n" }
  end
end

