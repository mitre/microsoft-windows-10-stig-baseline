control 'SV-220908' do
  title 'The built-in administrator account must be disabled.'
  desc 'The built-in administrator account is a well-known account subject to attack.  It also provides no accountability to individual administrators on a system.  It must be disabled to prevent its use.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Administrator account status" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Administrator account status" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22623r555209_chk'
  tag severity: 'medium'
  tag gid: 'V-220908'
  tag rid: 'SV-220908r958482_rule'
  tag stig_id: 'WN10-SO-000005'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-22612r555210_fix'
  tag 'documentable'
  tag legacy: ['SV-78091', 'V-63601']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  describe security_policy do
    its('EnableAdminAccount') { should cmp 0 }
  end
end
