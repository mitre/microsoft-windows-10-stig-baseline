control 'SV-220709' do
  title 'Alternate operating systems must not be permitted on the same system.'
  desc 'Allowing other operating systems to run on a secure system may allow security to be circumvented.'
  desc 'check', 'Verify the system does not include other operating system installations.

Run "Advanced System Settings".
Select the "Advanced" tab.
Click the "Settings" button in the "Startup and Recovery" section.

If the drop-down list box "Default operating system:" shows any operating system other than Windows 10, this is a finding.'
  desc 'fix', 'Ensure Windows 10 is the only operating system on a device.  Remove alternate operating systems.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22424r554612_chk'
  tag severity: 'medium'
  tag gid: 'V-220709'
  tag rid: 'SV-220709r991589_rule'
  tag stig_id: 'WN10-00-000055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22413r554613_fix'
  tag 'documentable'
  tag legacy: ['SV-77845', 'V-63355']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("bcdedit | Findstr description | Findstr /v /c:'Windows Boot Manager'") do
    its('stdout') { should eq "description             Windows 10\r\n" }
  end
end
