control 'SV-220729' do
  title 'The Server Message Block (SMB) v1 protocol must be disabled on the system.'
  desc 'SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a number of attacks such as collision and preimage attacks as well as not being FIPS compliant.

Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however Windows Server 2003 is no longer a supported operating system. Some older Network Attached Storage (NAS) devices may only support SMBv1.'
  desc 'check', 'Different methods are available to disable SMBv1 on Windows 10.  This is the preferred method, however if V-220730 and V-220731 are configured, this is NA.

Run "Windows PowerShell" with elevated privileges (run as administrator).

Enter the following:
Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol

If "State : Enabled" is returned, this is a finding.

Alternately:
Search for "Features".

Select "Turn Windows features on or off".

If "SMB 1.0/CIFS File Sharing Support" is selected, this is a finding.'
  desc 'fix', 'Disable the SMBv1 protocol.

Run "Windows PowerShell" with elevated privileges (run as administrator).

Enter the following:
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

Alternately:
Search for "Features".

Select "Turn Windows features on or off".

De-select "SMB 1.0/CIFS File Sharing Support".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22444r793186_chk'
  tag severity: 'medium'
  tag gid: 'V-220729'
  tag rid: 'SV-220729r958478_rule'
  tag stig_id: 'WN10-00-000160'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22433r554673_fix'
  tag 'documentable'
  tag legacy: ['V-70639', 'SV-85261']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  if registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mrxsmb10').has_property_value?('Start', :dword, 4) 
    impact 0.0
    desc 'This control is not applicable, as controls V-74725 is configured'
  else
    smb1protocol = json( command: 'Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol | ConvertTo-Csv | ConvertFrom-Csv | ConvertTo-Json').params
     describe 'Feature Name SMB1Protocol should not be Enabled' do
      subject { smb1protocol }
      its(['State']) { should_not eq "Enabled" }
     end
  end
end
