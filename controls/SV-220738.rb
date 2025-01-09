control 'SV-220738' do
  title 'Windows 10 nonpersistent VM sessions must not exceed 24 hours.'
  desc 'For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon logoff, the organization should enforce that sessions be terminated within 24 hours. This would ensure any data stored on the VM that is not encrypted or covered by Credential Guard is deleted.'
  desc 'check', 'Ensure there is a documented policy or procedure in place that nonpersistent VM sessions do not exceed 24 hours. If the system is NOT a nonpersistent VM, this is Not Applicable.

If no such documented policy or procedure is in place, this is a finding.'
  desc 'fix', 'Set nonpersistent VM sessions to not exceed 24 hours.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22453r890424_chk'
  tag severity: 'medium'
  tag gid: 'V-220738'
  tag rid: 'SV-220738r958552_rule'
  tag stig_id: 'WN10-00-000250'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-22442r890425_fix'
  tag 'documentable'
  tag legacy: ['V-102611', 'SV-111557']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
