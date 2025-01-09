control 'SV-257589' do
  title 'Windows 10 must have command line process auditing events enabled for failures.'
  desc 'When this policy setting is enabled, the operating system generates audit events when a process fails to start and the name of the program or user that created it.

These audit events can assist in understanding how a computer is being used and tracking user activity.'
  desc 'check', 'Ensure Audit Process Creation auditing has been enabled: 

Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >>System Audit Policies >> Detailed Tracking >> Audit Process Creation". 

If "Audit Process Creation" is not set to "Failure", this is a finding.'
  desc 'fix', 'Go to Computer Configuration >> Windows Settings >> Security Settings >> Advanced Audit Policy Configuration >>System Audit Policies >> Detailed Tracking >> Audit Process Creation is set to "failure".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-61326r951143_chk'
  tag severity: 'medium'
  tag gid: 'V-257589'
  tag rid: 'SV-257589r958412_rule'
  tag stig_id: 'WN10-AU-000585'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-61250r951144_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
