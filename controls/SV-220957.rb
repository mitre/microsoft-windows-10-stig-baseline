control 'SV-220957' do
  title 'The Access this computer from the network user right must only be assigned to the Administrators and Remote Desktop Users groups.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

Accounts with the "Access this computer from the network" user right may access resources on the system, and must be limited to those that require it.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Access this computer from the network" user right, this is a finding:

Administrators
Remote Desktop Users

If a domain application account such as for a management tool requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account, managed at the domain level, must meet requirements for application account passwords, such as length and frequency of changes as defined in the Windows server STIGs.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Access this computer from the network" to only include the following groups or accounts:

Administrators   
Remote Desktop Users'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22672r555356_chk'
  tag severity: 'medium'
  tag gid: 'V-220957'
  tag rid: 'SV-220957r958472_rule'
  tag stig_id: 'WN10-UR-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-22661r555357_fix'
  tag 'documentable'
  tag legacy: ['SV-78335', 'V-63845']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

    describe security_policy do
      its('SeNetworkLogonRight') { should be_in ['S-1-5-32-544', 'S-1-5-32-555'] }
    end
end
