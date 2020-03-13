control "V-63891" do
  title "The Increase scheduling priority user right on Windows 10 must only be
assigned to Administrators and Window Manager\\Window Manager Group."
  desc  "Inappropriate granting of user rights can provide system,
administrative, and other high level capabilities.

    Accounts with the \"Increase scheduling priority\" user right can change a
scheduling priority causing performance issues or a DoS.
  "
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-UR-000115"
  tag gid: "V-63891"
  tag rid: "SV-78381r2_rule"
  tag stig_id: "WN10-UR-000115"
  tag fix_id: "F-100995r1_fix"
  tag cci: ["CCI-002235"]
  tag nist: ["AC-6 (10)", "Rev_4"]
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
  tag check: "Verify the effective setting in Local Group Policy Editor.
Run \"gpedit.msc\".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings
>> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the \"Increase
scheduling priority\" user right, this is a finding:

Administrators
Window Manager\\Window Manager Group"
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Local Policies >> User Rights Assignment >>
\"Increase scheduling priority\" to only include the following groups or
accounts:

Administrators
Window Manager\\Window Manager Group"
  describe.one do
    describe security_policy do
      its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544', 'S-1-5-90-0'] }
    end
    describe security_policy do
      its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-32-544'] }
    end
    describe security_policy do
      its('SeIncreaseBasePriorityPrivilege') { should eq ['S-1-5-90-0'] }
    end 
    describe security_policy do
      its('SeIncreaseBasePriorityPrivilege') { should eq [] }
    end
  end
end

