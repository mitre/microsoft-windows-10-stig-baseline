control 'SV-220727' do
  title 'Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.'
  desc 'Attackers are constantly looking for vulnerabilities in systems and applications. Structured Exception Handling Overwrite Protection (SEHOP) blocks exploits that use the Structured Exception Handling overwrite technique, a common buffer overflow attack.'
  desc 'check', 'This is applicable to Windows 10 prior to v1709.

Verify SEHOP is turned on.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel\\

Value Name: DisableExceptionChainValidation

Value Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Enable Structured Exception Handling Overwrite Protection (SEHOP)" to "Enabled".

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22442r554666_chk'
  tag severity: 'high'
  tag gid: 'V-220727'
  tag rid: 'SV-220727r958928_rule'
  tag stig_id: 'WN10-00-000150'
  tag gtitle: 'SRG-OS-000433-GPOS-00192'
  tag fix_id: 'F-22431r554667_fix'
  tag 'documentable'
  tag legacy: ['SV-83445', 'V-68849']
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']

  if registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ReleaseId < '1709'
    impact 0.0
    describe 'This is applicable to Windows 10 prior to v1709.' do
      skip 'This is applicable to Windows 10 prior to v1709.'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel') do
      it { should have_property 'DisableExceptionChainValidation' }
      its('DisableExceptionChainValidation') { should cmp 0 }
    end
  end
end
