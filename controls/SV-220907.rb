control 'SV-220907' do
  title 'Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.'
  desc "The registry is integral to the function, security, and stability of the Windows system.  Changing the system's registry permissions allows the possibility of unauthorized and anonymous modification to the operating system."
  desc 'check', 'Verify the default registry permissions for the keys note below of the HKEY_LOCAL_MACHINE hive.

If any non-privileged groups such as Everyone, Users or Authenticated Users have greater than Read permission, this is a finding.

Run "Regedit".
Right click on the registry areas noted below.
Select "Permissions..." and the "Advanced" button.

HKEY_LOCAL_MACHINE\\SECURITY
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
SYSTEM - Full Control - This key and subkeys
Administrators - Special - This key and subkeys

HKEY_LOCAL_MACHINE\\SOFTWARE
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
Users - Read - This key and subkeys
Administrators - Full Control - This key and subkeys
SYSTEM - Full Control - This key and subkeys
CREATOR OWNER - Full Control - This key and subkeys
ALL APPLICATION PACKAGES - Read - This key and subkeys

HKEY_LOCAL_MACHINE\\SYSTEM
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
Users - Read - This key and subkeys
Administrators - Full Control - This key and subkeys
SYSTEM - Full Control - This key and subkeys
CREATOR OWNER - Full Control - This key and subkeys
ALL APPLICATION PACKAGES - Read - This key and subkeys

Other subkeys under the noted keys may also be sampled. There may be some instances where non-privileged groups have greater than Read permission.

Microsoft has given Read permission to the SOFTWARE and SYSTEM registry keys in later versions of Windows 10 to the following SID, this is currently not a finding.

S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681

If the defaults have not been changed, these are not a finding.'
  desc 'fix', 'Maintain the default permissions for the HKEY_LOCAL_MACHINE registry hive.

The default permissions of the higher level keys are noted below.

HKEY_LOCAL_MACHINE\\SECURITY
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
SYSTEM - Full Control - This key and subkeys
Administrators - Special - This key and subkeys

HKEY_LOCAL_MACHINE\\SOFTWARE
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
Users - Read - This key and subkeys
Administrators - Full Control - This key and subkeys
SYSTEM - Full Control - This key and subkeys
CREATOR OWNER - Full Control - This key and subkeys
ALL APPLICATION PACKAGES - Read - This key and subkeys

HKEY_LOCAL_MACHINE\\SYSTEM
Type - "Allow" for all
Inherited from - "None" for all
Principal - Access - Applies to
Users - Read - This key and subkeys
Administrators - Full Control - This key and subkeys
SYSTEM - Full Control - This key and subkeys
CREATOR OWNER - Full Control - This key and subkeys
ALL APPLICATION PACKAGES - Read - This key and subkeys

Microsoft has also given Read permission to the SOFTWARE and SYSTEM registry keys in later versions of Windows 10 to the following SID.

S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22622r555206_chk'
  tag severity: 'medium'
  tag gid: 'V-220907'
  tag rid: 'SV-220907r958726_rule'
  tag stig_id: 'WN10-RG-000005'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-22611r555207_fix'
  tag 'documentable'
  tag legacy: ['SV-78083', 'V-63593']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  # Adding Read permission for Security for Administrators to allow for read of key permissions

   hklm_software = powershell("(Get-Acl -Path HKLM:Software).AccessToString").stdout.lines.collect(&:strip)
    describe "Registry Key Software permissions are set correctly on folder structure" do
      subject { hklm_software.eql? input('reg_software_perms')}
      it { should eq true }
    end

   hklm_security = powershell("(Get-Acl -Path HKLM:Security).AccessToString").stdout.lines.collect(&:strip)
    describe "Registry Key Security are set correctly on folder structure" do
      subject { hklm_security.eql? input('reg_security_perms')}
      it { should eq true }
    end

   hklm_system = powershell("(Get-Acl -Path HKLM:System).AccessToString").stdout.lines.collect(&:strip)
    describe "Registry Key Security are set correctly on folder structure" do
      subject { hklm_system.eql? input('reg_system_perms')}
      it { should eq true }
    end
end
