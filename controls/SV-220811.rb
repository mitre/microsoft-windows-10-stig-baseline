control 'SV-220811' do
  title 'Virtualization Based Security must be enabled on Windows 10 with the platform security level configured to Secure Boot or Secure Boot with DMA Protection.'
  desc 'Virtualization Based Security (VBS) provides the platform for the additional security features, Credential Guard and Virtualization based protection of code integrity. Secure Boot is the minimum security level with DMA protection providing additional memory protection.  DMA Protection requires a CPU that supports input/output memory management unit (IOMMU).'
  desc 'check', 'Confirm virtualization-based security (VBS) is enabled and running with Secure Boot or Secure Boot and DMA Protection.

For those devices that support VBS features, including Credential Guard or protection of code integrity, this must be enabled. If the system meets the hardware and firmware dependencies for enabling VBS but it is not enabled, this is a CAT III finding.

VBS, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Run "PowerShell" with elevated privileges (run as administrator).

Enter the following:

"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard"

If "RequiredSecurityProperties" does not include a value of "2" indicating "Secure Boot" (e.g., "{1, 2}"), this is a finding.

If "Secure Boot and DMA Protection" is configured, "3" will also be displayed in the results (e.g., "{1, 2, 3}").

If "VirtualizationBasedSecurityStatus" is not a value of "2" indicating "Running", this is a finding.

Alternately:

Run "System Information".

Under "System Summary", verify the following:

If "Device Guard Virtualization based security" does not display "Running", this is finding.

If "Device Guard Required Security Properties" does not display "Base Virtualization Support, Secure Boot", this is finding.

If "Secure Boot and DMA Protection" is configured, "DMA Protection" will also be displayed (e.g., "Base Virtualization Support, Secure Boot, DMA Protection").

The policy settings referenced in the Fix section will configure the following registry values. However, due to hardware requirements, the registry values alone do not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

Value Name: EnableVirtualizationBasedSecurity
Value Type: REG_DWORD
Value: 1

Value Name: RequirePlatformSecurityFeatures
Value Type: REG_DWORD
Value: 1 (Secure Boot only) or 3 (Secure Boot and DMA Protection)

A Microsoft article on Credential Guard system requirements can be found at the following link:

https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard-requirements'
  desc 'fix', 'VBS, including Credential Guard, currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >> "Turn On Virtualization Based Security" to "Enabled" with "Secure Boot" or "Secure Boot and DMA Protection" selected for "Select Platform Security Level:".

A Microsoft article on Credential Guard system requirements can be found at the following link:
https://technet.microsoft.com/en-us/itpro/windows/keep-secure/credential-guard-requirements'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22526r1016347_chk'
  tag severity: 'medium'
  tag gid: 'V-220811'
  tag rid: 'SV-220811r1016359_rule'
  tag stig_id: 'WN10-CC-000070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22515r1016348_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
