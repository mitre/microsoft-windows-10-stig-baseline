# -*- encoding : utf-8 -*-

control 'V-63567' do
  title "The system must be configured to ignore NetBIOS name release requests
        except from WINS servers."
  desc  "Configuring the system to ignore name release requests, except from
        WINS servers, prevents a denial of service (DoS) attack. The DoS consists of
        sending a NetBIOS name release request to the server for each entry in the
        server's cache, causing a response delay in the normal operation of the servers
        WINS resolution capability."

  impact 0.3

  tag severity: 'low'
  tag gtitle: 'WN10-CC-000035'
  tag gid: 'V-63567'
  tag rid: 'SV-78057r1_rule'
  tag stig_id: 'WN10-CC-000035'
  tag fix_id: 'F-69497r1_fix'
  tag cci: ['CCI-002385']
  tag nist: %w[SC-5 Rev_4]
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

      Registry Hive:  HKEY_LOCAL_MACHINE
      Registry Path:  \\SYSTEM\\CurrentControlSet\\Services\\Netbt\\Parameters\\

      Value Name:  NoNameReleaseOnDemand

      Value Type:  REG_DWORD
      Value:  1"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> MSS (Legacy) >> \"MSS: (NoNameReleaseOnDemand)
      Allow the computer to ignore NetBIOS name release requests except from WINS
      servers\" to \"Enabled\".

      This policy setting requires the installation of the MSS-Legacy custom
      templates included with the STIG package.  \"MSS-Legacy.admx\" and \"
      MSS-Legacy.adml\" must be copied to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively."

  describe registry_key('HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters') do
    it { should have_property 'NoNameReleaseOnDemand' }
    its('NoNameReleaseOnDemand') { should cmp 1 }
  end
end

