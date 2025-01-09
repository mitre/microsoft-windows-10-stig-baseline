control 'SV-220845' do
  title 'Windows 10 must be configured to disable Windows Game Recording and Broadcasting.'
  desc 'Windows Game Recording and Broadcasting is intended for use with games, however it could potentially record screen shots of other applications and expose sensitive data.  Disabling the feature will prevent this from occurring.'
  desc 'check', 'This is NA for Windows 10 LTSC\\B versions 1507 and 1607.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR\\

Value Name: AllowGameDVR

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Game Recording and Broadcasting >> "Enables or disables Windows Game Recording and Broadcasting" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22560r555020_chk'
  tag severity: 'medium'
  tag gid: 'V-220845'
  tag rid: 'SV-220845r958478_rule'
  tag stig_id: 'WN10-CC-000252'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22549r555021_fix'
  tag 'documentable'
  tag legacy: ['SV-89091', 'V-74417']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  releaseID = registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId.to_i

  if ( releaseID == 1607 || releaseID <= 1507 )
    impact 0.0
    describe 'This STIG does not apply to Prior Versions before 1507 and 1607.' do
      skip 'This STIG does not apply to Prior Versions before 1507 and 1607.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR') do
      it { should have_property 'AllowGameDVR' }
      its('AllowGameDVR') { should cmp 0 }
    end
  end
end
