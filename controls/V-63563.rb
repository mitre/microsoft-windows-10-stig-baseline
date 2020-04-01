# -*- encoding : utf-8 -*-

control 'V-63563' do
  title "The system must be configured to prevent Internet Control Message
        Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF)
        generated routes."
  desc  "Allowing ICMP redirect of routes can lead to traffic not being routed
        properly.   When disabled, this forces ICMP to be routed via shortest path
        first."

  impact 0.3

  tag severity: 'low'
  tag gtitle: 'WN10-CC-000030'
  tag gid: 'V-63563'
  tag rid: 'SV-78053r1_rule'
  tag stig_id: 'WN10-CC-000030'
  tag fix_id: 'F-69493r1_fix'
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
      Registry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\

      Value Name: EnableICMPRedirect

      Value Type: REG_DWORD
      Value: 0"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> MSS (Legacy) >> \"MSS: (EnableICMPRedirect) Allow
      ICMP redirects to override OSPF generated routes\" to \"Disabled\".

      This policy setting requires the installation of the MSS-Legacy custom
      templates included with the STIG package.  \"MSS-Legacy.admx\" and \"
      MSS-Legacy.adml\" must be copied to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively."

  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters') do
    it { should have_property 'EnableICMPRedirect' }
    its('EnableICMPRedirect') { should cmp 0 }
  end
end

