# -*- encoding : utf-8 -*-

control 'V-63633' do
  title 'Local users on domain-joined computers must not be enumerated.'
  desc  "The username is one part of logon credentials that could be used to
        gain access to a system.  Preventing the enumeration of users limits this
        information to authorized personnel."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-CC-000130'
  tag gid: 'V-63633'
  tag rid: 'SV-78123r1_rule'
  tag stig_id: 'WN10-CC-000130'
  tag fix_id: 'F-69565r1_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a', 'Rev_4']
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

  desc "check", "This requirement is applicable to domain-joined systems, for
      standalone systems this is NA.

      If the following registry value does not exist or is not configured as
      specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\System\\

      Value Name: EnumerateLocalUsers

      Value Type: REG_DWORD
      Value: 0"

  desc "fix", "This requirement is applicable to domain-joined systems, for
      standalone systems this is NA.

      Configure the policy value for Computer Configuration >> Administrative
      Templates >> System >> Logon >> \"Enumerate local users on domain-joined
      computers\" to \"Disabled\"."

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if is_domain != 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System') do
      it { should have_property 'EnumerateLocalUsers' }
      its('EnumerateLocalUsers') { should cmp 0 }
    end
  end
end

