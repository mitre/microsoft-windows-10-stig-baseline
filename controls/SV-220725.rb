control 'SV-220725' do
  title 'Inbound exceptions to the firewall on Windows 10 domain workstations must only allow authorized remote management hosts.'
  desc 'Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if credentials are compromised.  Limiting inbound connections only from authorized remote management systems will help limit this exposure.'
  desc 'check', 'Verify firewall exceptions to inbound connections on domain workstations include only authorized remote management hosts.

If allowed inbound exceptions are not limited to authorized remote management hosts, this is a finding.

Review inbound firewall exceptions.
Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Inbound Rules (this link will be in the right pane)

For any inbound rules that allow connections view the Scope for Remote IP address. This may be defined as an IP address, subnet, or range. The rule must apply to all firewall profiles.

If a third-party firewall is used, ensure comparable settings are in place.'
  desc 'fix', 'Configure firewall exceptions to inbound connections on domain workstations to include only authorized remote management hosts.

Configure only inbound connection exceptions for authorized remote management hosts.
Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced Security >> Windows Defender Firewall with Advanced Security >> Inbound Rules (this link will be in the right pane)

For any inbound rules that allow connections, configure the Scope for Remote IP address to those of authorized remote management hosts. This may be defined as an IP address, subnet or range. Apply the rule to all firewall profiles.

If a third-party firewall is used, configure inbound exceptions to only include authorized remote management hosts.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22440r554660_chk'
  tag severity: 'medium'
  tag gid: 'V-220725'
  tag rid: 'SV-220725r991589_rule'
  tag stig_id: 'WN10-00-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22429r554661_fix'
  tag 'documentable'
  tag legacy: ['V-63403', 'SV-77893']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'A manual review of any inbound firewall rules that allow connections to unauthorized connections. Also check for third-party firewalls' do
    skip 'A manual review of any inbound firewall rules that allow connections'
  end
end
