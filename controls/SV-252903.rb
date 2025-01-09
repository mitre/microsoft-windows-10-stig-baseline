control 'SV-252903' do
  title 'Virtualization-based protection of code integrity must be enabled.'
  desc 'Virtualization-based protection of code integrity enforces kernel mode memory protections and protects Code Integrity validation paths. This isolates the processes from the rest of the operating system and can only be accessed by privileged system software.'
  desc 'check', 'Confirm virtualization-based protection of code integrity.

For devices that support the virtualization based security (VBS) feature for protection of code integrity, this must be enabled. If the system meets the hardware, firmware, and compatible device driver dependencies for enabling virtualization-based protection of code integrity but it is not enabled, this is a CAT II finding.

Virtualization based security currently cannot be implemented in virtual desktop implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Run "PowerShell" with elevated privileges (run as administrator).
Enter the following:
"Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard"

If "SecurityServicesRunning" does not include a value of "2" (e.g., "{1, 2}"), this is a finding.

Alternately:

Run "System Information".

Under "System Summary", verify the following:
If "Virtualization-based Security Services Running" does not list "Hypervisor enforced Code Integrity", this is finding.

The policy settings referenced in the Fix section will configure the following registry value. However due to hardware requirements, the registry value alone does not ensure proper function.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceGuard\\

Value Name: HypervisorEnforcedCodeIntegrity
Value Type: REG_DWORD
Value: 0x00000001 (1) (Enabled with UEFI lock), or 0x00000002 (2) (Enabled without lock)'
  desc 'fix', 'Virtualization-based security currently cannot be implemented in VDIs due to specific supporting requirements, including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V feature within the virtual desktop.

For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >> "Turn On Virtualization Based Security" to "Enabled" with "Enabled with UEFI lock" or "Enabled without lock" selected for "Virtualization Based Protection of Code Integrity:".

"Enabled with UEFI lock" is preferred as more secure; however, it cannot be turned off remotely through a group policy change if there is an issue.

"Enabled without lock" will allow this to be turned off remotely while testing for issues.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-56359r822501_chk'
  tag severity: 'low'
  tag gid: 'V-252903'
  tag rid: 'SV-252903r991589_rule'
  tag stig_id: 'WN10-CC-000080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56309r822502_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
