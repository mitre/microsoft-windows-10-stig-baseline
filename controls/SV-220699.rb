control 'SV-220699' do
  title 'Windows 10 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in UEFI mode, not Legacy BIOS.'
  desc 'UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot. UEFI is required to support additional security features in Windows 10, including Virtualization Based Security and Credential Guard. Systems with UEFI that are operating in Legacy BIOS mode will not support these security features.'
  desc 'check', 'For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

Verify the system firmware is configured to run in UEFI mode, not Legacy BIOS.

Run "System Information".

Under "System Summary", if "BIOS Mode" does not display "UEFI", this is a finding.'
  desc 'fix', 'Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22414r642137_chk'
  tag severity: 'medium'
  tag gid: 'V-220699'
  tag rid: 'SV-220699r991589_rule'
  tag stig_id: 'WN10-00-000015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22403r554583_fix'
  tag 'documentable'
  tag legacy: ['V-77083', 'SV-91779']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if sys_info.manufacturer != 'VMware, Inc.'
    describe 'Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode' do
      skip 'Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode'
    end
  else
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-77083.' do
      skip 'This is a VDI System; This System is NA for Control V-77083.'
    end
 end
end
