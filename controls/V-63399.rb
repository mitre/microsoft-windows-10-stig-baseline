# -*- encoding : utf-8 -*-

control 'V-63399' do
  title 'A host-based firewall must be installed and enabled on the system.'
  desc  "A firewall provides a line of defense against attack, allowing or
        blocking inbound and outbound connections based on a set of rules."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000135'
  tag gid: 'V-63399'
  tag rid: 'SV-77889r1_rule'
  tag stig_id: 'WN10-00-000135'
  tag fix_id: 'F-69327r1_fix'
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

  desc "check", "Determine if a host-based firewall is installed and enabled on
      the system.  If a host-based firewall is not installed and enabled on the
        system, this is a finding.

        The configuration requirements will be determined by the applicable firewall
        STIG."

  desc "fix", 'Install and enable a host-based firewall on the system.'
 
   query_domain = json({ command: "Get-WmiObject -NameSpace 'root\\standardcimv2' -Class MSFT_NetFirewallProfile | Where {$_.Name -Like 'Domain' } | Select Enabled | ConvertTo-Json" })
   query_private = json({ command: "Get-WmiObject -NameSpace 'root\\standardcimv2' -Class MSFT_NetFirewallProfile | Where {$_.Name -Like 'Private' } | Select Enabled | ConvertTo-Json" })
   query_public = json({ command: "Get-WmiObject -NameSpace 'root\\standardcimv2' -Class MSFT_NetFirewallProfile | Where {$_.Name -Like 'Public' } | Select Enabled | ConvertTo-Json" })
  
    describe.one do
     describe 'Windows Firewall should be Enabled' do
      subject { query_public.params["Enabled"] }
      it 'The Public host-based firewall' do
      failure_message = "is not Enabled"
      expect(subject).to eql(1), failure_message
      end
     end
     describe 'Windows Firewall should be Enabled' do
     subject { query_private.params["Enabled"] }
     it 'The Private host-based firewall' do
     failure_message = "is not enabled"
     expect(subject).to eql(1), failure_message
     end
    end
    describe 'Windows Firewall should be Enabled' do
     subject { query_domain.params["Enabled"] }
     it 'The Domain host-based firewall' do
     failure_message = "is not Enabled"
     expect(subject).to eql(1), failure_message
     end
    end
  end
end

