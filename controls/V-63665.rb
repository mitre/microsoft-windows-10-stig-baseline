# -*- encoding : utf-8 -*-
control "V-63665" do
  title "The system must be configured to require a strong session key."
  desc  "A computer connecting to a domain controller will establish a secure
        channel.  Requiring strong session keys enforces 128-bit encryption between
        systems."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "WN10-SO-000060"
  tag gid: "V-63665"
  tag rid: "SV-78155r1_rule"
  tag stig_id: "WN10-SO-000060"
  tag fix_id: "F-69593r1_fix"
  tag cci: ["CCI-002418", "CCI-002421"]
  tag nist: ["SC-8", "SC-8 (1)", "Rev_4"]
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters\\

      Value Name: RequireStrongKey

      Value Type: REG_DWORD
      Value: 1

      Warning: This setting may prevent a system from being joined to a domain if not
      configured consistently between systems."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"Domain
      member: Require strong (Windows 2000 or Later) session key\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters') do
    it { should have_property 'RequireStrongKey' }
    its('RequireStrongKey') { should cmp 1 }
  end
end


