control 'SV-220700' do
  title 'Secure Boot must be enabled on Windows 10 systems.'
  desc 'Secure Boot is a standard that ensures systems boot only to a trusted operating system. Secure Boot is required to support additional security features in Windows 10, including Virtualization Based Security and Credential Guard. If Secure Boot is turned off, these security features will not function.'
  desc 'check', 'Some older systems may not have UEFI firmware. This is currently a CAT III; it will be raised in severity at a future date when broad support of Windows 10 hardware and firmware requirements are expected to be met. Devices that have UEFI firmware must have Secure Boot enabled. 

For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Run "System Information".

Under "System Summary", if "Secure Boot State" does not display "On", this is finding.'
  desc 'fix', 'Enable Secure Boot in the system firmware.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22415r554585_chk'
  tag severity: 'low'
  tag gid: 'V-220700'
  tag rid: 'SV-220700r991589_rule'
  tag stig_id: 'WN10-00-000020'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22404r554586_fix'
  tag 'documentable'
  tag legacy: ['SV-91781', 'V-77085']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  uefi_boot = json( command: 'Confirm-SecureBootUEFI | ConvertTo-Json').params
  if sys_info.manufacturer != 'VMware, Inc.' || nil
    describe 'Confirm-Secure Boot UEFI is required to be enabled on System' do
      subject { uefi_boot }
      it { should_not eq 'False' }
    end
  else
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-77085.' do
      skip 'This is a VDI System; This System is NA for Control V-77085.'
    end
  end
end
