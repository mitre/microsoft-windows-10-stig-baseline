control 'SV-220909' do
  title 'The built-in guest account must be disabled.'
  desc 'A system faces an increased vulnerability threat if the built-in guest account is not disabled.  This account is a known account that exists on all Windows systems and cannot be deleted.  This account is initialized during the installation of the operating system with no password assigned.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Guest account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22624r555212_chk'
  tag severity: 'medium'
  tag gid: 'V-220909'
  tag rid: 'SV-220909r958504_rule'
  tag stig_id: 'WN10-SO-000010'
  tag gtitle: 'SRG-OS-000121-GPOS-00062'
  tag fix_id: 'F-22613r555213_fix'
  tag 'documentable'
  tag legacy: ['V-63611', 'SV-78101']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']

  describe security_policy do
    its('EnableGuestAccount') { should cmp 0 }
  end
end
