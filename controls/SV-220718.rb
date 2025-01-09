control 'SV-220718' do
  title 'Internet Information System (IIS) or its subcomponents must not be installed on a workstation.'
  desc 'Installation of Internet Information System (IIS) may allow unauthorized internet services to be hosted.  Websites must only be hosted on servers that have been designed for that purpose and can be adequately secured.'
  desc 'check', 'IIS is not installed by default.  Verify it has not been installed on the system.

Run "Programs and Features".
Select "Turn Windows features on or off".

If the entries for "Internet Information Services" or "Internet Information Services Hostable Web Core" are selected, this is a finding.

If an application requires IIS or a subset to be installed to function, this needs be documented with the ISSO.  In addition, any applicable requirements from the IIS STIG must be addressed.'
  desc 'fix', 'Uninstall "Internet Information Services" or "Internet Information Services Hostable Web Core" from the system.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22433r554639_chk'
  tag severity: 'high'
  tag gid: 'V-220718'
  tag rid: 'SV-220718r958478_rule'
  tag stig_id: 'WN10-00-000100'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22422r554640_fix'
  tag 'documentable'
  tag legacy: ['V-63377', 'SV-77867']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe windows_feature('Internet Information Services') do
    it { should_not be_installed }
  end
end
