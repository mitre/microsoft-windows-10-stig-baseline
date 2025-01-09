control 'SV-220923' do
  title 'Caching of logon credentials must be limited.'
  desc "The default Windows configuration caches the last logon credentials for users who log on interactively to a system.  This feature is provided for system availability reasons, such as the user's machine being disconnected from the network or domain controllers being unavailable.  Even though the credential cache is well-protected, if a system is attacked, an unauthorized individual may isolate the password to a domain user account using a password-cracking program and gain access to the domain."
  desc 'check', 'This is the default configuration for this setting (10 logons to cache).

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE 
Registry Path:  \\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name:  CachedLogonsCount

Value Type:  REG_SZ
Value:  10 (or less)

This setting only applies to domain-joined systems, however, it is configured by default on all systems.'
  desc 'fix', 'This is the default configuration for this setting (10 logons to cache).

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Interactive logon: Number of previous logons to cache (in case domain controller is not available)" to "10" logons or less.

This setting only applies to domain-joined systems, however, it is configured by default on all systems.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22638r555254_chk'
  tag severity: 'low'
  tag gid: 'V-220923'
  tag rid: 'SV-220923r991589_rule'
  tag stig_id: 'WN10-SO-000085'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22627r555255_fix'
  tag 'documentable'
  tag legacy: ['SV-78177', 'V-63687']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon') do
    it { should have_property 'CachedLogonsCount' }
    its('CachedLogonsCount') { should cmp <= 10 }
  end
end
