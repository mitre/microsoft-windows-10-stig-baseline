# -*- encoding : utf-8 -*-

control 'V-63555' do
  title 'IPv6 source routing must be configured to highest protection.'
  desc  "Configuring the system to disable IPv6 source routing protects against
        spoofing."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000020'
  tag gid: 'V-63555'
  tag rid: 'SV-78045r1_rule'
  tag stig_id: 'WN10-CC-000020'
  tag fix_id: 'F-69485r1_fix'
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

  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\

      Value Name: DisableIpSourceRouting

      Value Type: REG_DWORD
      Value: 2"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> MSS (Legacy) >> \"MSS: (DisableIPSourceRouting
      IPv6) IP source routing protection level (protects against packet spoofing)\"
      to \"Highest protection, source routing is completely disabled\".

      This policy setting requires the installation of the MSS-Legacy custom
      templates included with the STIG package.  \"MSS-Legacy.admx\" and \"
      MSS-Legacy.adml\" must be copied to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively."

  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters') do
    it { should have_property 'DisableIPSourceRouting' }
    its('DisableIPSourceRouting') { should cmp 2 }
  end
end

