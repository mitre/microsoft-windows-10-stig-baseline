control 'SV-220736' do
  title 'The system must notify the user when a Bluetooth device attempts to connect.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised'
  desc 'check', 'This is NA if the system does not have Bluetooth, or if Bluetooth is turned off per the organizations policy.

Search for "Bluetooth".
View Bluetooth Settings.
Select "More Bluetooth Options"
If "Alert me when a new Bluetooth device wants to connect" is not checked, this is a finding.'
  desc 'fix', 'Configure Bluetooth to notify users if devices attempt to connect.
View Bluetooth Settings.
Ensure "Alert me when a new Bluetooth device wants to connect" is checked.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22451r554693_chk'
  tag severity: 'medium'
  tag gid: 'V-220736'
  tag rid: 'SV-220736r991589_rule'
  tag stig_id: 'WN10-00-000230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22440r554694_fix'
  tag 'documentable'
  tag legacy: ['SV-87407', 'V-72769']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  if sys_info.manufacturer != 'VMware, Inc.'
    describe 'Configure Bluetooth to notify users if devices attempt to connect.
              View Bluetooth Settings. Ensure "Alert me when a new Bluetooth device 
              wants to connect" is checked' do
      skip 'This is NA if the system does not have Bluetooth'
    end
  else
    impact 0.0
    describe 'This is a VDI System; This System is NA for Control V-72769.' do
      skip 'This is a VDI System; This System is NA for Control V-72769.'
    end
  end
end
