control 'SV-220739' do
  title 'Windows 10 account lockout duration must be configured to 15 minutes or greater.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.   This parameter specifies the amount of time that an account will remain locked after the specified number of failed logon attempts.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout duration" is less than "15" minutes (excluding "0"), this is a finding.

Configuring this to "0", requiring an administrator to unlock the account, is more restrictive and is not a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Account lockout duration" to "15" minutes or greater.

A value of "0" is also acceptable, requiring an administrator to unlock the account.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22454r554702_chk'
  tag severity: 'medium'
  tag gid: 'V-220739'
  tag rid: 'SV-220739r958736_rule'
  tag stig_id: 'WN10-AC-000005'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-22443r554703_fix'
  tag 'documentable'
  tag legacy: ['SV-77895', 'V-63405']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  # issues has been raised to fix the IF statement for describe.one to allow for inputs
  pass_lock_time = input('pass_lock_time')

  describe.one do
    describe security_policy do
      its('LockoutDuration') { should cmp >= pass_lock_time }
    end
    describe security_policy do
      its('LockoutDuration') { should cmp 0 }
    end
  end
end
