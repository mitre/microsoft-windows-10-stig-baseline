control 'SV-268319' do
  title 'Windows 10 systems must use either Group Policy or an approved Mobile Device Management (MDM) product to enforce STIG compliance.'
  desc 'Without Windows 10 systems being managed, devices could be rogue and become targets of an attacker.'
  desc 'check', 'Verify the Windows 10 system is receiving policy from either Group Policy or an MDM with the following steps:

From a command line or PowerShell:

gpresult /R
OS Configuration: Member Workstation

If the system is not being managed by GPO, ask the administrator to indicate which MDM is managing the device.

If the Window 10 system is not receiving policy from either Group Policy or an MDM, this is a finding.'
  desc 'fix', 'Configure the Windows 10 system to use either Group Policy or an approved MDM product to enforce STIG compliance.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-72340r1028350_chk'
  tag severity: 'medium'
  tag gid: 'V-268319'
  tag rid: 'SV-268319r1028350_rule'
  tag stig_id: 'WN10-CC-000063'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-72243r1028256_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
