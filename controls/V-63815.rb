# -*- encoding : utf-8 -*-

control 'V-63815' do
  title 'The default permissions of global system objects must be increased.'
  desc  "Windows systems maintain a global list of shared system resources such
        as DOS device names, mutexes, and semaphores. Each type of object is created
        with a default DACL that specifies who can access the objects with what
        permissions. If this policy is enabled, the default DACL is stronger, allowing
        non-admin users to read shared objects, but not modify shared objects that they
        did not create."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'WN10-SO-000240'
  tag gid: 'V-63815'
  tag rid: 'SV-78305r1_rule'
  tag stig_id: 'WN10-SO-000240'
  tag fix_id: 'F-69743r1_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b', 'Rev_4']
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
  desc "check", "If the following registry value does not exist or is not
      configured as specified, this is a finding:

      Registry Hive: HKEY_LOCAL_MACHINE
      Registry Path: \\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\

      Value Name: ProtectionMode

      Value Type: REG_DWORD
      Value: 1"
  desc "fix", "Configure the policy value for Computer Configuration >> Windows
      Settings >> Security Settings >> Local Policies >> Security Options >> \"System
      objects: Strengthen default permissions of internal system objects (e.g.
      Symbolic links)\" to \"Enabled\"."

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager') do
    it { should have_property 'ProtectionMode' }
    its('ProtectionMode') { should cmp 1 }
  end
end

