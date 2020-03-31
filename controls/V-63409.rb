# -*- encoding : utf-8 -*-

control 'V-63409' do
  title "The number of allowed bad logon attempts must be configured to
        #{input('max_pass_lockout')} or less."
  desc  "The account lockout feature, when enabled, prevents brute-force
        password attacks on the system.  The higher this value is, the less effective
        the account lockout feature will be in protecting the local system.  The number
        of bad logon attempts must be reasonably small to minimize the possibility of a
        successful password attack, while allowing for honest errors made during a
        normal user logon."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AC-000010'
  tag gid: 'V-63409'
  tag rid: 'SV-77899r1_rule'
  tag stig_id: 'WN10-AC-000010'
  tag fix_id: 'F-69337r1_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a', 'Rev_4']
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

  desc "check", "Verify the effective setting in Local Group Policy Editor.
        Run \"gpedit.msc\".

        Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
        >> Security Settings >> Account Policies >> Account Lockout Policy.

        If the \"Account lockout threshold\" is \"0\" or more than #{input('max_pass_lockout')} attempts,
        this is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
        Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
        \"Account lockout threshold\" to #{input('max_pass_lockout')} or less invalid logon attempts
        (excluding \"0\" which is unacceptable)."

  describe security_policy do
    its('LockoutBadCount') { should be <= input('max_pass_lockout') }
  end
  describe security_policy do
    its('LockoutBadCount') { should be_positive }
  end
end

