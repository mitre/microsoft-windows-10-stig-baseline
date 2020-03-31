# -*- encoding : utf-8 -*-

control 'V-63581' do
  title "Simultaneous connections to the Internet or a Windows domain must be
        limited."
  desc  "Multiple network connections can provide additional attack vectors to
        a system and must be limited. The \"Minimize the number of simultaneous
        connections to the Internet or a Windows Domain\" setting prevents systems from
        automatically establishing multiple connections.  When both wired and wireless
        connections are available, for example, the less preferred connection
        (typically wireless) will be disconnected."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000055'
  tag gid: 'V-63581'
  tag rid: 'SV-78071r2_rule'
  tag stig_id: 'WN10-CC-000055'
  tag fix_id: 'F-69511r1_fix'
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

  desc "check", "The default behavior for \"Minimize the number of simultaneous
      connections to the Internet or a Windows Domain\" is \"Enabled\".

      If the registry value name below does not exist, this is not a finding.

      If it exists and is configured with a value of \"1\", this is not a finding.

      If it exists and is configured with a value of \"0\", this is a finding.

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WcmSvc\\GroupPolicy\\

      Value Name: fMinimizeConnections

      Value Type: REG_DWORD
      Value: 1 (or if the Value Name does not exist)"

  desc "fix", "The default behavior for \"Minimize the number of simultaneous
      connections to the Internet or a Windows Domain\" is \"Enabled\".

      If this needs to be corrected, configure the policy value for Computer
      Configuration >> Administrative Templates >> Network >> Windows Connection
      Manager >> \"Minimize the number of simultaneous connections to the Internet or
      a Windows Domain\" to \"Enabled\"."

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe.one do
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
        it { should_not have_property 'fMinimizeConnections' }
      end
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy') do
        its('fMinimizeConnections') { should cmp 1 }
      end
    end
  end
end

