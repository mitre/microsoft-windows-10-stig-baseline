control 'SV-220928' do
  title 'Anonymous SID/Name translation must not be allowed.'
  desc 'Allowing anonymous SID/Name translation can provide sensitive information for accessing a system.  Only authorized users must be able to perform such translations.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options.

If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Allow anonymous SID/Name translation" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22643r555269_chk'
  tag severity: 'high'
  tag gid: 'V-220928'
  tag rid: 'SV-220928r991589_rule'
  tag stig_id: 'WN10-SO-000140'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22632r555270_fix'
  tag 'documentable'
  tag legacy: ['V-63739', 'SV-78229']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe security_policy do
    its('LSAAnonymousNameLookup') { should eq 0 }
  end
end
