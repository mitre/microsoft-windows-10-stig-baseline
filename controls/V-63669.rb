# -*- encoding : utf-8 -*-

control 'V-63669' do
  title "The machine inactivity limit must be set to 15 minutes, locking the
        system with the screensaver."
  desc  "Unattended systems are susceptible to unauthorized use and should be
        locked when unattended.  The screen saver should be set at a maximum of 15
        minutes and be password protected.  This protects critical and sensitive data
        from exposure to unauthorized personnel with physical access to the computer."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000070'
  tag gid: 'V-63669'
  tag rid: 'SV-78159r2_rule'
  tag stig_id: 'WN10-SO-000070'
  tag fix_id: 'F-88429r1_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a', 'Rev_4']
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

      Value Name: InactivityTimeoutSecs

      Value Type: REG_DWORD
      Value: 0x00000384 (900) (or less, excluding \"0\" which is effectively
      disabled)"

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Interactive logon: Machine inactivity limit\" to \"900\" seconds\" or less,
      excluding \"0\" which is effectively disabled."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'InactivityTimeoutSecs' }
    its('InactivityTimeoutSecs') { should be <= 900 }
  end
  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    its('InactivityTimeoutSecs') { should be_positive }
  end
end

