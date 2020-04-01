# -*- encoding : utf-8 -*-

control 'V-63697' do
  title "The Smart Card removal option must be configured to Force Logoff or
        Lock Workstation."
  desc  "Unattended systems are susceptible to unauthorized use and must be
        locked.  Configuring a system to lock when a smart card is removed will ensure
        the system is inaccessible when unattended."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-SO-000095'
  tag gid: 'V-63697'
  tag rid: 'SV-78187r1_rule'
  tag stig_id: 'WN10-SO-000095'
  tag fix_id: 'F-69625r1_fix'
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

      Registry Hive:  HKEY_LOCAL_MACHINE
      Registry Path:  \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

      Value Name:  SCRemoveOption

      Value Type:  REG_SZ
      Value:  1 (Lock Workstation) or 2 (Force Logoff)

      This can be left not configured or set to \"No action\" on workstations with
      the following conditions.  This must be documented with the ISSO.
      -The setting cannot be configured due to mission needs, or because it
      interferes with applications.
      -Policy must be in place that users manually lock workstations when leaving
      them unattended.
      -The screen saver is properly configured to lock as required."
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >>
      \"Interactive logon: Smart card removal behavior\" to  \"Lock Workstation\" or
      \"Force Logoff\"."

  describe.one do
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
      it { should have_property 'SCRemoveOption' }
      its('SCRemoveOption') { should cmp 1 }
    end
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
      it { should have_property 'SCRemoveOption' }
      its('SCRemoveOption') { should cmp 2 }
    end
  end
end

