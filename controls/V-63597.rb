# -*- encoding : utf-8 -*-

control 'V-63597' do
  title "Local administrator accounts must have their privileged token filtered
        to prevent elevated privileges from being used over the network on domain
        systems."

  desc  "A compromised local administrator account can provide means for an
        attacker to move laterally between domain systems.

        With User Account Control enabled, filtering the privileged token for
        built-in administrator accounts will prevent the elevated privileges of these
        accounts from being used over the network."

  impact 0.5

  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000037'
  tag gid: 'V-63597'
  tag rid: 'SV-78087r2_rule'
  tag stig_id: 'WN10-CC-000037'
  tag fix_id: 'F-78099r3_fix'
  tag cci: ['CCI-001084']
  tag nist: %w[SC-3 Rev_4]
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

  desc "check", "If the system is not a member of a domain, this is NA.

      If the following registry value does not exist or is not configured as
      specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

      Value Name: LocalAccountTokenFilterPolicy

      Value Type: REG_DWORD
      Value: 0x00000000 (0)"

  desc "fix", "Configure the policy value for Computer Configuration >>
      Administrative Templates >> MS Security Guide >> \"Apply UAC restrictions to
      local accounts on network logons\" to \"Enabled\".

      This policy setting requires the installation of the SecGuide custom templates
      included with the STIG package.  \"SecGuide.admx\" and \"SecGuide.adml\" must
      be copied to the \\Windows\\PolicyDefinitions and
      \\Windows\\PolicyDefinitions\\en-US directories respectively."

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
      it { should have_property 'LocalAccountTokenFilterPolicy' }
      its('LocalAccountTokenFilterPolicy') { should cmp 0 }
    end
  end
end

