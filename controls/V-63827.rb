# -*- encoding : utf-8 -*-

control 'V-63827' do
  title "User Account Control must only elevate UIAccess applications that are
        installed in secure locations."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
        elevation of privileges, including administrative accounts, unless authorized.
        This setting configures Windows to only allow applications installed in a
        secure location on the file system, such as the Program Files or the
        Windows\\System32 folders, to run with elevated privileges."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000265'
  tag gid: 'V-63827'
  tag rid: 'SV-78317r1_rule'
  tag stig_id: 'WN10-SO-000265'
  tag fix_id: 'F-69755r1_fix'
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

      Value Name: EnableSecureUIAPaths

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"User
      Account Control: Only elevate UIAccess applications that are installed in
      secure locations\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'EnableSecureUIAPaths' }
    its('EnableSecureUIAPaths') { should cmp 1 }
  end
end

