control 'SV-220746' do
  title 'The built-in Microsoft password complexity filter must be enabled.'
  desc 'The use of complex passwords increases their strength against guessing and brute-force attacks.  This setting configures the system to verify that newly created passwords conform to the Windows password complexity policy.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for "Password must meet complexity requirements" is not set to "Enabled", this is a finding.

If the site is using a password filter that requires this setting be set to "Disabled" for the filter to be used, this would not be considered a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Password must meet complexity requirements" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22461r554723_chk'
  tag severity: 'medium'
  tag gid: 'V-220746'
  tag rid: 'SV-220746r1016408_rule'
  tag stig_id: 'WN10-AC-000040'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-22450r554724_fix'
  tag 'documentable'
  tag legacy: ['SV-77917', 'V-63427']
  tag cci: ['CCI-000366', 'CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-001619', 'CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-001619']
  tag nist: ['CM-6 b', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']

  describe security_policy do
    its('PasswordComplexity') { should eq input('enable_pass_complexity') }
  end
end
