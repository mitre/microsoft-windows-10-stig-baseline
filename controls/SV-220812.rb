control 'SV-220812' do
  title 'Credential Guard must be running on Windows 10 domain-joined systems.'
  desc 'Credential Guard uses virtualization based security to protect information that could be used in credential theft attacks if compromised. This authentication information, which was stored in the Local Security Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be accessed by privileged system software.'
  desc 'check', 'Confirm Credential Guard is running on domain-joined systems.

For devices that support Credential Guard, this feature must be enabled. Organizations must take the appropriate action to acquire and implement compatible hardware with Credential Guard enabled.

Virtualization based security, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDIs) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is Not Applicable.

Run "PowerShell" with elevated privileges (run as administrator). 

Enter the following:
"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard"

If "SecurityServicesRunning" does not include a value of "1" (e.g., "{1, 2}"), this is a finding.

Alternately:

Run "System Information".

Under "System Summary", verify the following:

If "Virtualization-based Security Services Running" does not list "Credential Guard", this is finding.

The policy settings referenced in the Fix section will configure the following registry value. However, due to hardware requirements, the registry value alone does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

Value Name: LsaCfgFlags
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock)'
  desc 'fix', 'Virtualization based security, including Credential Guard, currently cannot be implemented in VDIs due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is Not Applicable.

For VDIs with persistent desktops, this may be downgraded to a CAT II only where administrators have specific tokens for the VDI. Administrator accounts on virtual desktops must only be used on systems in the VDI; they may not have administrative privileges on any other systems such as servers and physical workstations.

Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >> "Turn On Virtualization Based Security" to "Enabled" with "Enabled with UEFI lock" selected for "Credential Guard Configuration:".

v1507 LTSB does not include selection options; select "Enable Credential Guard".

A Microsoft TechNet article on Credential Guard, including system requirement details, can be found at the following link:

https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22527r890428_chk'
  tag severity: 'high'
  tag gid: 'V-220812'
  tag rid: 'SV-220812r991589_rule'
  tag stig_id: 'WN10-CC-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22516r890429_fix'
  tag 'documentable'
  tag legacy: ['SV-78089', 'V-63599']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  is_domain = command('wmic computersystem get domain | FINDSTR /V Domain').stdout.strip

  if sys_info.manufacturer == 'VMware, Inc.'
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-63599.' do
      skip 'This is a VDI System; This System is NA for Control V-63599.'
    end
  elsif is_domain == 'WORKGROUP'
    impact 0.0
    describe 'The system is not a member of a domain, control is NA' do
      skip 'The system is not a member of a domain, control is NA'
    end
  else
    describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard') do
      it { should have_property 'LsaCfgFlags' }
      its('LsaCfgFlags') { should cmp 1 }
    end
  end
end
