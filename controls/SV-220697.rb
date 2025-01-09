control 'SV-220697' do
  title 'Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version.'
  desc 'Features such as Credential Guard use virtualization-based security to protect information that could be used in credential theft attacks if compromised. A number of system requirements must be met for Credential Guard to be configured and enabled properly. Virtualization-based security and Credential Guard are only available with Windows 10 Enterprise 64-bit version.'
  desc 'check', 'Verify domain-joined systems are using Windows 10 Enterprise Edition 64-bit version.

For standalone or nondomain-joined systems, this is NA.

Open "Settings".

Select "System", then "About".

If "Edition" is not "Windows 10 Enterprise", this is a finding.

If "System type" is not "64-bit operating system…", this is a finding.'
  desc 'fix', 'Use Windows 10 Enterprise 64-bit version for domain-joined systems.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22412r857177_chk'
  tag severity: 'medium'
  tag gid: 'V-220697'
  tag rid: 'SV-220697r991589_rule'
  tag stig_id: 'WN10-00-000005'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22401r554577_fix'
  tag 'documentable'
  tag legacy: ['V-63319', 'SV-77809']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe os.arch do
    it { should eq 'x86_64' }
  end

  describe os.name do
    it { should eq 'windows_10_enterprise' }
  end
end
