# -*- encoding : utf-8 -*-

control 'V-63831' do
  title "User Account Control must virtualize file and registry write failures
        to per-user locations."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
        elevation of privileges, including administrative accounts, unless authorized.
        This setting configures non-UAC compliant applications to run in virtualized
        file and registry entries in per-user locations, allowing them to run."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000275'
  tag gid: 'V-63831'
  tag rid: 'SV-78321r1_rule'
  tag stig_id: 'WN10-SO-000275'
  tag fix_id: 'F-69759r1_fix'
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
  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path:
      \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\

      Value Name: EnableVirtualization

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"User
      Account Control: Virtualize file and registry write failures to per-user
      locations\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'EnableVirtualization' }
    its('EnableVirtualization') { should cmp 1 }
  end
end

