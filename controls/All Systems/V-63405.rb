control "V-63405" do
  title "Windows 10 account lockout duration must be configured to 15 minutes
or greater."
  desc  "The account lockout feature, when enabled, prevents brute-force
password attacks on the system.   This parameter specifies the amount of time
that an account will remain locked after the specified number of failed logon
attempts."
  impact 0.5
  tag severity: nil
  tag gtitle: "WN10-AC-000005"
  tag gid: "V-63405"
  tag rid: "SV-77895r2_rule"
  tag stig_id: "WN10-AC-000005"
  tag fix_id: "F-81277r1_fix"
  tag cci: ["CCI-002238"]
  tag nist: ["AC-7 b", "Rev_4"]
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
>> Security Settings >> Account Policies >> Account Lockout Policy.

If the \"Account lockout duration\" is less than \"15\" minutes (excluding
\"0\"), this is a finding.

Configuring this to \"0\", requiring an administrator to unlock the account, is
more restrictive and is not a finding."
  tag fix: "Configure the policy value for Computer Configuration >> Windows
Settings >> Security Settings >> Account Policies >> Account Lockout Policy >>
\"Account lockout duration\" to \"15\" minutes or greater.

A value of \"0\" is also acceptable, requiring an administrator to unlock the
account."

  describe.one do
    describe security_policy do
      its('LockoutDuration') { should be >= 15 }
    end
    describe security_policy do
      its('LockoutDuration') { should cmp 0 }
    end
  end 
end

