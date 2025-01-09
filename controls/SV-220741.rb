control 'SV-220741' do
  title 'The period of time before the bad logon counter is reset must be configured to 15 minutes.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This parameter specifies the period of time that must pass after failed logon attempts before the counter is reset to 0.  The smaller this value is, the less effective the account lockout feature will be in protecting the local system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Reset account lockout counter after" to "15" minutes.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22456r554708_chk'
  tag severity: 'medium'
  tag gid: 'V-220741'
  tag rid: 'SV-220741r958388_rule'
  tag stig_id: 'WN10-AC-000015'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-22445r554709_fix'
  tag 'documentable'
  tag legacy: ['V-63413', 'SV-77903']
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']

  describe security_policy do
    its('ResetLockoutCount') { should be >= input('pass_lock_time') }
  end
end
