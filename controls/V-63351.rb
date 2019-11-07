control "V-63351" do
  title "The Windows 10 system must use an anti-virus program."
  desc  "Malicious software can establish a base on individual desktops and
servers. Employing an automated mechanism to detect this type of software will
aid in elimination of the software from the operating system."
  impact 0.7
  tag severity: nil
  tag gtitle: "WN10-00-000045"
  tag gid: "V-63351"
  tag rid: "SV-77841r4_rule"
  tag stig_id: "WN10-00-000045"
  tag fix_id: "F-83183r1_fix"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b", "Rev_4"]
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
  tag check: "Verify an anti-virus solution is installed on the system. The
anti-virus solution may be bundled with an approved host-based security
solution.

If there is no anti-virus solution installed on the system, this is a finding."
  tag fix: "Install an anti-virus solution on the system."
end

