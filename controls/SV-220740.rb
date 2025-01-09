control 'SV-220740' do
  title 'The number of allowed bad logon attempts must be configured to 3 or less.'
  desc 'The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher this value is, the less effective the account lockout feature will be in protecting the local system.  The number of bad logon attempts must be reasonably small to minimize the possibility of a successful password attack, while allowing for honest errors made during a normal user logon.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy.

If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Account Lockout Policy >> "Account lockout threshold" to "3" or less invalid logon attempts (excluding "0" which is unacceptable).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22455r554705_chk'
  tag severity: 'medium'
  tag gid: 'V-220740'
  tag rid: 'SV-220740r958388_rule'
  tag stig_id: 'WN10-AC-000010'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-22444r554706_fix'
  tag 'documentable'
  tag legacy: ['SV-77899', 'V-63409']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']

  describe security_policy do
    its('LockoutBadCount') { should be <= input('max_pass_lockout') }
  end
  describe security_policy do
    its('LockoutBadCount') { should be_positive }
  end
end
