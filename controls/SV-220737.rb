control 'SV-220737' do
  title 'Administrative accounts must not be used with applications that access the Internet, such as web browsers, or with potential Internet sources, such as email.'
  desc 'Using applications that access the Internet or have potential Internet sources using administrative privileges exposes a system to compromise. If a flaw in an application is exploited while running as a privileged user, the entire system could be compromised. Web browsers and email are common attack vectors for introducing malicious code and must not be run with an administrative account.

Since administrative accounts may generally change or work around technical restrictions for running a web browser or other applications, it is essential that policy requires administrative accounts to not access the Internet or use applications, such as email.

The policy should define specific exceptions for local service administration. These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.

Technical means such as application whitelisting can be used to enforce the policy to ensure compliance.'
  desc 'check', 'Determine whether administrative accounts are prevented from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, except as necessary for local service administration.

The organization must have a policy that prohibits administrative accounts from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email, except as necessary for local service administration. The policy should define specific exceptions for local service administration. These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.

Technical measures such as the removal of applications or application whitelisting must be used where feasible to prevent the use of applications that access the Internet. 

If accounts with administrative privileges are not prevented from using applications that access the Internet or with potential Internet sources, this is a finding.'
  desc 'fix', 'Establish and enforce a policy that prohibits administrative accounts from using applications that access the Internet, such as web browsers, or with potential Internet sources, such as email. Define specific exceptions for local service administration. These exceptions may include HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.

Implement technical measures where feasible such as removal of applications or use of application whitelisting to restrict the use of applications that can access the Internet.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22452r554696_chk'
  tag severity: 'high'
  tag gid: 'V-220737'
  tag rid: 'SV-220737r991589_rule'
  tag stig_id: 'WN10-00-000240'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22441r554697_fix'
  tag 'documentable'
  tag legacy: ['V-78129', 'SV-92835']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'Establish and enforce a policy that prohibits administrative account from using applications that access the Internet' do
    skip 'Implement technical measures where feasible such as removal of application
   or use of application whitelisting to restrict the use of applications that can access Internet'
  end
end
