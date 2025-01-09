control 'SV-220946' do
  title 'Windows 10 must use multifactor authentication for local and network access to privileged and nonprivileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged and nonprivileged functions is greatly increased. 

All domain accounts must be enabled for multifactor authentication with the exception of local emergency accounts. 

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 

1) Something a user knows (e.g., password/PIN);
2) Something a user has (e.g., cryptographic identification device, token); and
3) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'If the system is not a member of a domain, this is Not Applicable.

If one of the following settings does not exist and is not populated, this is a finding: 

Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\Readers
Computer\\HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Calais\\SmartCards'
  desc 'fix', "For nondomain-joined systems, configuring Windows Hello for sign-on options is suggested based on the organization's needs and capabilities."
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22661r921922_chk'
  tag severity: 'medium'
  tag gid: 'V-220946'
  tag rid: 'SV-220946r958484_rule'
  tag stig_id: 'WN10-SO-000251'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-22650r921923_fix'
  tag satisfies: ['SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag legacy: ['SV-111577', 'V-102627']
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
