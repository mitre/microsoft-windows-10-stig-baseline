control 'SV-220704' do
  title 'Windows 10 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.'
  desc 'If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even when the operating system is not running. Pre-boot authentication prevents unauthorized users from accessing encrypted drives. Increasing the PIN length requires a greater number of guesses for an attacker.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon logoff, this is NA.

For Azure Virtual Desktop (AVD) implementations with no data at rest, this is NA.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\FVE\\

Value Name: MinimumPIN
Type: REG_DWORD
Value: 0x00000006 (6) or greater'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> BitLocker Drive Encryption >> Operating System Drives "Configure minimum PIN length for startup" to "Enabled" with "Minimum characters:" set to "6" or greater.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22419r819654_chk'
  tag severity: 'high'
  tag gid: 'V-220704'
  tag rid: 'SV-220704r958552_rule'
  tag stig_id: 'WN10-00-000032'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-22408r554598_fix'
  tag 'documentable'
  tag legacy: ['SV-104691', 'V-94861']
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']

   if sys_info.manufacturer == "VMware, Inc."
      impact 0.0
      describe 'This is a VDI System; This System is NA for Control V-94861.' do
       skip 'This is a VDI System; This System is NA for Control V-94861'
      end
   else
      describe registry_key('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Bitlocker') do
       it { should have_property 'MinimumPIN' }
       its('MinimumPIN') { should be >= input('bitlocker_pin_len') }
  end
 end
end
