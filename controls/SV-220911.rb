control 'SV-220911' do
  title 'The built-in administrator account must be renamed.'
  desc 'The built-in administrator account is a well-known account subject to attack.  Renaming this account to an unidentified name improves the protection of this account and the system.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Accounts: Rename administrator account" is set to "Administrator", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Accounts: Rename administrator account" to a name other than "Administrator".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22626r555218_chk'
  tag severity: 'medium'
  tag gid: 'V-220911'
  tag rid: 'SV-220911r991589_rule'
  tag stig_id: 'WN10-SO-000020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22615r555219_fix'
  tag 'documentable'
  tag legacy: ['SV-78109', 'V-63619']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe user('Administrator') do
    it { should_not exist }
  end
end
