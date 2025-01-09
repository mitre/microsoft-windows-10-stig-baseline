control 'SV-220745' do
  title 'Passwords must, at a minimum, be 14 characters.'
  desc 'Information systems not protected with strong password schemes (including passwords of minimum length) provide the opportunity for anyone to crack the password, thus gaining access to the system and compromising the device, information, or the local network.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy.

If the value for the "Minimum password length," is less than "14" characters, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account Policies >> Password Policy >> "Minimum password length" to "14" characters.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22460r554720_chk'
  tag severity: 'medium'
  tag gid: 'V-220745'
  tag rid: 'SV-220745r1016407_rule'
  tag stig_id: 'WN10-AC-000035'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-22449r554721_fix'
  tag 'documentable'
  tag legacy: ['SV-77913', 'V-63423']
  tag cci: ['CCI-004066', 'CCI-000205', 'CCI-000205']
  tag nist: ['IA-5 (1) (h)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']

  describe security_policy do
    its('MinimumPasswordLength') { should be >= input('min_pass_len') }
  end
end
