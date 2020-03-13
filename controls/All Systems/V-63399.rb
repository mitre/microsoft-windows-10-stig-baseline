control "V-63399" do
  title "A host-based firewall must be installed and enabled on the system."
  desc  "A firewall provides a line of defense against attack, allowing or
blocking inbound and outbound connections based on a set of rules."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-00-000135"
  tag gid: "V-63399"
  tag rid: "SV-77889r1_rule"
  tag stig_id: "WN10-00-000135"
  tag fix_id: "F-69327r1_fix"
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
  tag check: "Determine if a host-based firewall is installed and enabled on
the system.  If a host-based firewall is not installed and enabled on the
system, this is a finding.

The configuration requirements will be determined by the applicable firewall
STIG."
  tag fix: "Install and enable a host-based firewall on the system."
  describe 'A host-based firewall must be installed and enabled on the system' do
    skip 'is a manual check'
  end
  describe registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Software\\Policies\\Microsoft\\Windows Defender\\DomainProfile") do
    it { should have_property 'EnableFirewall' }
    its('EnableFirewall') { should cmp 1 }
  end
end

