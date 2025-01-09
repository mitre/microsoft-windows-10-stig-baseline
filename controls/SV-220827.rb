control 'SV-220827' do
  title 'Autoplay must be turned off for non-volume devices.'
  desc 'Allowing autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive as soon as you insert media in the drive.  As a result, the setup file of programs or music on audio media may start.  This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP) devices).'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoAutoplayfornonVolume

Value Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> AutoPlay Policies >> "Disallow Autoplay for non-volume devices" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22542r554966_chk'
  tag severity: 'high'
  tag gid: 'V-220827'
  tag rid: 'SV-220827r958804_rule'
  tag stig_id: 'WN10-CC-000180'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-22531r554967_fix'
  tag 'documentable'
  tag legacy: ['SV-78157', 'V-63667']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']

  describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer') do
    it { should have_property 'NoAutoplayfornonVolume' }
    its('NoAutoplayfornonVolume') { should cmp 1 }
  end
end
