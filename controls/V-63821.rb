# -*- encoding : utf-8 -*-
control "V-63821" do
  title "User Account Control must automatically deny elevation requests for 
        standard users."
  desc  "User Account Control (UAC) is a security mechanism for limiting the
        elevation of privileges, including administrative accounts, unless authorized.
        Denying elevation requests from standard user accounts requires tasks that need
        elevation to be initiated by accounts with administrative privileges.  This
        ensures correct accounts are used on the system for privileged tasks to help
        mitigate credential theft."
  impact 0.5
  tag severity: "medium"
  tag gtitle: "WN10-SO-000255"
  tag gid: "V-63821"
  tag rid: "SV-78311r1_rule"
  tag stig_id: "WN10-SO-000255"
  tag fix_id: "F-69749r1_fix"
  tag cci: ["CCI-002038"]
  tag nist: ["IA-11", "Rev_4"]
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

      Value Name: ConsentPromptBehaviorUser

      Value Type: REG_DWORD
      Value: 0"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"User
      Account Control: Behavior of the elevation prompt for standard users\" to
      \"Automatically deny elevation requests\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') do
    it { should have_property 'ConsentPromptBehaviorUser' }
    its('ConsentPromptBehaviorUser') { should cmp 0 }
  end
end


