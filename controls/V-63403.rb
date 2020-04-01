# -*- encoding : utf-8 -*-

control 'V-63403' do
  title "Inbound exceptions to the firewall on Windows 10 domain workstations
        must only allow authorized remote management hosts."
  desc  "Allowing inbound access to domain workstations from other systems may
        allow lateral movement across systems if credentials are compromised.  Limiting
        inbound connections only from authorized remote management systems will help
        limit this exposure."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000140'
  tag gid: 'V-63403'
  tag rid: 'SV-77893r2_rule'
  tag stig_id: 'WN10-00-000140'
  tag fix_id: 'F-100991r1_fix'
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

  desc "check", "Verify firewall exceptions to inbound connections on domain
      workstations include only authorized remote management hosts.

      If allowed inbound exceptions are not limited to authorized remote management
      hosts, this is a finding.

      Review inbound firewall exceptions.
      Computer Configuration >> Windows Settings >> Security Settings >> Windows
      Defender Firewall with Advanced Security >> Windows Defender Firewall with
      Advanced Security >> Inbound Rules (this link will be in the right pane)

      For any inbound rules that allow connections view the Scope for Remote IP
      address. This may be defined as an IP address, subnet, or range. The rule must
      apply to all firewall profiles.

      If a third-party firewall is used, ensure comparable settings are in place."

  desc "fix", "Configure firewall exceptions to inbound connections on domain
      workstations to include only authorized remote management hosts.

      Configure only inbound connection exceptions for authorized remote management
      hosts.
      Computer Configuration >> Windows Settings >> Security Settings >> Windows
      Defender Firewall with Advanced Security >> Windows Defender Firewall with
      Advanced Security >> Inbound Rules (this link will be in the right pane)

      For any inbound rules that allow connections, configure the Scope for Remote IP
      address to those of authorized remote management hosts. This may be defined as
      an IP address, subnet or range. Apply the rule to all firewall profiles.

      If a third-party firewall is used, configure inbound exceptions to only include
      authorized remote management hosts."

  describe 'A manual review of any inbound firewall rules that allow connections to unauthorized connections. Also check for third-party firewalls' do
    skip 'A manual review of any inbound firewall rules that allow connections'
  end
end

