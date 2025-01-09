control 'SV-220933' do
  title 'Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.'
  desc "The Windows Security Account Manager (SAM) stores users' passwords.  Restricting remote rpc connections to the SAM to Administrators helps protect those credentials."
  desc 'check', 'Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Lsa\\

Value Name: RestrictRemoteSAM

Value Type: REG_SZ
Value: O:BAG:BAD:(A;;RC;;;BA)'
  desc 'fix', 'Navigate to the policy Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network access: Restrict clients allowed to make remote calls to SAM".

Select "Edit Security" to configure the "Security descriptor:".

Add "Administrators" in "Group or user names:" if it is not already listed (this is the default).

Select "Administrators" in "Group or user names:".

Select "Allow" for "Remote Access" in "Permissions for "Administrators".

Click "OK".

The "Security descriptor:" must be populated with "O:BAG:BAD:(A;;RC;;;BA) for the policy to be enforced.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22648r555284_chk'
  tag severity: 'medium'
  tag gid: 'V-220933'
  tag rid: 'SV-220933r958726_rule'
  tag stig_id: 'WN10-SO-000167'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22637r555285_fix'
  tag 'documentable'
  tag legacy: ['SV-86393', 'V-71769']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId != '1507'
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa') do
      it { should have_property 'RestrictRemoteSAM' }
      its('RestrictRemoteSAM') { should cmp 'O:BAG:BAD:(A;;RC;;;BA)' }
    end
  else
    impact 0.0
    describe 'Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.' do
      skip 'Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.'
    end
  end
end
