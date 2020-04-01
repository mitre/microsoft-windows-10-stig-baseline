# -*- encoding : utf-8 -*-

control 'V-63413' do
  title "The period of time before the bad logon counter is reset must be
        configured to #{input('pass_lock_time')} minutes."
  desc  "The account lockout feature, when enabled, prevents brute-force
        password attacks on the system.  This parameter specifies the period of time
        that must pass after failed logon attempts before the counter is reset to 0.
        The smaller this value is, the less effective the account lockout feature will
        be in protecting the local system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-AC-000015'
  tag gid: 'V-63413'
  tag rid: 'SV-77903r1_rule'
  tag stig_id: 'WN10-AC-000015'
  tag fix_id: 'F-69341r1_fix'
  tag cci: %w[CCI-000044 CCI-002238]
  tag nist: ['AC-7 a', 'AC-7 b', 'Rev_4']
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

      If the \"Reset account lockout counter after\" value is less than #{input('pass_lock_time')}
      minutes, this is a finding."

  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
      \"Reset account lockout counter after\" to #{input('pass_lock_time')} minutes."

  describe security_policy do
    its('ResetLockoutCount') { should be >= input('pass_lock_time') }
  end
end

