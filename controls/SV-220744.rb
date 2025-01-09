control 'SV-220744' do
  title 'The minimum password age must be configured to at least 1 day.'
  desc 'Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords through their history database. This enables users to effectively negate the purpose of mandating periodic password changes.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Minimum password age" is less than "1" day, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Minimum Password Age" to at least "1" day.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22459r554717_chk'
  tag severity: 'medium'
  tag gid: 'V-220744'
  tag rid: 'SV-220744r1016406_rule'
  tag stig_id: 'WN10-AC-000030'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-22448r554718_fix'
  tag 'documentable'
  tag legacy: ['V-63421', 'SV-77911']
  tag cci: ['CCI-004066', 'CCI-000198', 'CCI-000198']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (d)', 'IA-5 (1) (d)']

  describe security_policy do
    its('MinimumPasswordAge') { should be >= input('min_pass_age') }
  end
end
