# encoding: utf-8

control 'V-63593' do
  title "Default permissions for the HKEY_LOCAL_MACHINE registry hive must be
        maintained."
  desc  "The registry is integral to the function, security, and stability of
        the Windows system.  Changing the system's registry permissions allows the
        possibility of unauthorized and anonymous modification to the operating system."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-RG-000005'
  tag gid: 'V-63593'
  tag rid: 'SV-78083r2_rule'
  tag stig_id: 'WN10-RG-000005'
  tag fix_id: 'F-98471r1_fix'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)', 'Rev_4']
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: false
  tag mitigations: nil
  tag severity_override_guidance: false
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: nil

  desc 'check', "Verify the default registry permissions for the keys note below
      of the HKEY_LOCAL_MACHINE hive.

      If any non-privileged groups such as Everyone, Users or Authenticated Users
      have greater than Read permission, this is a finding.

      Run \"Regedit\".
      Right click on the registry areas noted below.
      Select \"Permissions...\" and the \"Advanced\" button.

      HKEY_LOCAL_MACHINE\\SECURITY
      Type - \"Allow\" for all
      Inherited from - \"None\" for all
      Principal - Access - Applies to
      SYSTEM - Full Control - This key and subkeys
      Administrators - Special - This key and subkeys

      HKEY_LOCAL_MACHINE\\SOFTWARE
      Type - \"Allow\" for all
      Inherited from - \"None\" for all
      Principal - Access - Applies to
      Users - Read - This key and subkeys
      Administrators - Full Control - This key and subkeys
      SYSTEM - Full Control - This key and subkeys
      CREATOR OWNER - Full Control - This key and subkeys
      ALL APPLICATION PACKAGES - Read - This key and subkeys

      HKEY_LOCAL_MACHINE\\SYSTEM
      Type - \"Allow\" for all
      Inherited from - \"None\" for all
      Principal - Access - Applies to
      Users - Read - This key and subkeys
      Administrators - Full Control - This key and subkeys
      SYSTEM - Full Control - This key and subkeys
      CREATOR OWNER - Full Control - This key and subkeys
      ALL APPLICATION PACKAGES - Read - This key and subkeys

      Other subkeys under the noted keys may also be sampled. There may be some
      instances where non-privileged groups have greater than Read permission.

      Microsoft has given Read permission to the SOFTWARE and SYSTEM registry keys in
      later versions of Windows 10 to the following SID, this is currently not a
      finding.

      S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681

      If the defaults have not been changed, these are not a finding."

  desc 'fix', "Maintain the default permissions for the HKEY_LOCAL_MACHINE
      registry hive.

      The default permissions of the higher level keys are noted below.

      HKEY_LOCAL_MACHINE\\SECURITY
      Type - \"Allow\" for all
      Inherited from - \"None\" for all
      Principal - Access - Applies to
      SYSTEM - Full Control - This key and subkeys
      Administrators - Special - This key and subkeys

      HKEY_LOCAL_MACHINE\\SOFTWARE
      Type - \"Allow\" for all
      Inherited from - \"None\" for all
      Principal - Access - Applies to
      Users - Read - This key and subkeys
      Administrators - Full Control - This key and subkeys
      SYSTEM - Full Control - This key and subkeys
      CREATOR OWNER - Full Control - This key and subkeys
      ALL APPLICATION PACKAGES - Read - This key and subkeys

      HKEY_LOCAL_MACHINE\\SYSTEM
      Type - \"Allow\" for all
      Inherited from - \"None\" for all
      Principal - Access - Applies to
      Users - Read - This key and subkeys
      Administrators - Full Control - This key and subkeys
      SYSTEM - Full Control - This key and subkeys
      CREATOR OWNER - Full Control - This key and subkeys
      ALL APPLICATION PACKAGES - Read - This key and subkeys

      Microsoft has also given Read permission to the SOFTWARE and SYSTEM registry
      keys in later versions of Windows 10 to the following SID.

      S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681"

  # Adding Read permission for Security for Administrators to allow for read of key permissions

  hklm_software = <<-EOH
  $output = (Get-Acl -Path HKLM:Software).AccessToString
  write-output $output
  EOH

  hklm_security = <<-EOH
  $output = (Get-Acl -Path HKLM:Security.AccessToString
  write-output $output
  EOH

  hklm_system = <<-EOH
  $output = (Get-Acl -Path HKLM:System).AccessToString
  write-output $output
  EOH

  # raw powershell output
  raw_software = powershell(hklm_software).stdout.strip
  raw_security = powershell(hklm_security).stdout.strip
  raw_system = powershell(hklm_system).stdout.strip

  # clean results cleans up the extra line breaks
  clean_result_software = raw_software.lines.collect(&:strip)
  clean_result_security = raw_security.lines.collect(&:strip)
  clean_result_system = raw_system.lines.collect(&:strip)

  describe 'Verify the default registry permissions for the keys note below of the HKEY_LOCAL_MACHINE\Software Hive' do
    subject { clean_result_software }
    it { should be_in input('reg_software_perms') }
  end

  describe 'Verify the default registry permissions for the keys note below of the HKEY_LOCAL_MACHINE\Security Hive' do
    subject { clean_result_security }
    it { should be_in input('reg_security_perms') }
  end

  describe 'Verify the default registry permissions for the keys note below of the HKEY_LOCAL_MACHINE\System Hive' do
    subject { clean_result_system }
    it { should be_in input('reg_system_perms') }
  end
end
