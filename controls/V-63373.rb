# -*- encoding : utf-8 -*-

control 'V-63373' do
  title "Permissions for system files and directories must conform to minimum
        requirements."
  desc  "Changing the system's file and directory permissions allows the
        possibility of unauthorized and anonymous modification to the operating system
        and installed applications."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000095'
  tag gid: 'V-63373'
  tag rid: 'SV-77863r2_rule'
  tag stig_id: 'WN10-00-000095'
  tag fix_id: 'F-69295r1_fix'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)', 'Rev_4']
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
  desc 'check', "The default file system permissions are adequate when the
        Security Option \"Network access: Let Everyone permissions apply to anonymous
        users\" is set to \"Disabled\" (WN10-SO-000160).

        If the default file system permissions are maintained and the referenced option
        is set to \"Disabled\", this is not a finding.

        Verify the default permissions for the sample directories below. Non-privileged
        groups such as Users or Authenticated Users must not have greater than Read &
        execute permissions except where noted as defaults. (Individual accounts must
        not be used to assign permissions.)

        Viewing in File Explorer:
        Select the \"Security\" tab, and the \"Advanced\" button.

        C:\\
        Type - \"Allow\" for all
        Inherited from - \"None\" for all
        Principal - Access - Applies to
        Administrators - Full control - This folder, subfolders and files
        SYSTEM - Full control - This folder, subfolders and files
        Users - Read & execute - This folder, subfolders and files
        Authenticated Users - Modify - Subfolders and files only
        Authenticated Users - Create folders / append data - This folder only

        \\Program Files
        Type - \"Allow\" for all
        Inherited from - \"None\" for all
        Principal - Access - Applies to
        TrustedInstaller - Full control - This folder and subfolders
        SYSTEM - Modify - This folder only
        SYSTEM - Full control - Subfolders and files only
        Administrators - Modify - This folder only
        Administrators - Full control - Subfolders and files only
        Users - Read & execute - This folder, subfolders and files
        CREATOR OWNER - Full control - Subfolders and files only
        ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files
        ALL RESTRICTED APPLICATION PACKAGES - Read & execute - This folder, subfolders
        and files

        \\Windows
        Type - \"Allow\" for all
        Inherited from - \"None\" for all
        Principal - Access - Applies to
        TrustedInstaller - Full control - This folder and subfolders
        SYSTEM - Modify - This folder only
        SYSTEM - Full control - Subfolders and files only
        Administrators - Modify - This folder only
        Administrators - Full control - Subfolders and files only
        Users - Read & execute - This folder, subfolders and files
        CREATOR OWNER - Full control - Subfolders and files only
        ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files
        ALL RESTRICTED APPLICATION PACKAGES - Read & execute - This folder, subfolders
        and files

        Alternately use icacls.

        Run \"CMD\" as administrator.
        Enter \"icacls\" followed by the directory.

        icacls c:\\
        icacls \"c:\\program files\"
        icacls c:\\windows

        The following results will be displayed as each is entered:

        c:\\
        BUILTIN\\Administrators:(OI)(CI)(F)
        NT AUTHORITY\\SYSTEM:(OI)(CI)(F)
        BUILTIN\\Users:(OI)(CI)(RX)
        NT AUTHORITY\\Authenticated Users:(OI)(CI)(IO)(M)
        NT AUTHORITY\\Authenticated Users:(AD)
        Mandatory Label\\High Mandatory Level:(OI)(NP)(IO)(NW)
        Successfully processed 1 files; Failed processing 0 files

        c:\\program files
        NT SERVICE\\TrustedInstaller:(F)
        NT SERVICE\\TrustedInstaller:(CI)(IO)(F)
        NT AUTHORITY\\SYSTEM:(M)
        NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
        BUILTIN\\Administrators:(M)
        BUILTIN\\Administrators:(OI)(CI)(IO)(F)
        BUILTIN\\Users:(RX)
        BUILTIN\\Users:(OI)(CI)(IO)(GR,GE)
        CREATOR OWNER:(OI)(CI)(IO)(F)
        APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(RX)
        APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
        APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(RX)
        APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION
        PACKAGES:(OI)(CI)(IO)(GR,GE)
        Successfully processed 1 files; Failed processing 0 files

        c:\\windows
        NT SERVICE\\TrustedInstaller:(F)
        NT SERVICE\\TrustedInstaller:(CI)(IO)(F)
        NT AUTHORITY\\SYSTEM:(M)
        NT AUTHORITY\\SYSTEM:(OI)(CI)(IO)(F)
        BUILTIN\\Administrators:(M)
        BUILTIN\\Administrators:(OI)(CI)(IO)(F)
        BUILTIN\\Users:(RX)
        BUILTIN\\Users:(OI)(CI)(IO)(GR,GE)
        CREATOR OWNER:(OI)(CI)(IO)(F)
        APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(RX)
        APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
        APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES:(RX)
        APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION
        PACKAGES:(OI)(CI)(IO)(GR,GE)
        Successfully processed 1 files; Failed processing 0 files"

  desc 'fix', "Maintain the default file system permissions and configure the
        Security Option: \"Network access: Let everyone permissions apply to anonymous
        users\" to \"Disabled\" (WN10-SO-000160)."


  c_windows_permission = JSON.parse(input('c_windows_folder_permissions').to_json)
  c_permission = JSON.parse(input('c_folder_permissions').to_json)
  c_program_files_permissions = JSON.parse(input('c_program_files_folder_permissions').to_json)

  query_c_windows = json({ command: 'icacls "c:\\windows" | ConvertTo-Json' }).params.map { |e| e.strip }[0..-3].map{ |e| e.gsub("c:\\windows ", '') }
  query_c = json( command: "icacls 'C:\\' | ConvertTo-Json").params.map { |e| e.strip }[0..-3].map{ |e| e.gsub("C:\\ ", '') }
  query_c_program_files = json({ command: 'icacls "c:\\Program Files" | ConvertTo-Json' }).params.map { |e| e.strip }[0..-3].map{ |e| e.gsub("c:\\Program Files ", '') }

  describe 'The ACL on C:\Windows are set to the right permissions' do
    subject { query_c_windows }
    it { should be_in c_windows_permission }
  end
  describe 'The ACL on C:\ are set to the right permissions' do
    subject { query_c }
    it { should be_in c_permission }
  end
  describe 'The ACL on C:\Program Files are set to the right permissions' do
    subject { query_c_program_files }
    it { should be_in c_program_files_permissions }
  end
end
