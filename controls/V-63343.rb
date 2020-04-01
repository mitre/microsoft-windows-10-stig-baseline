# -*- encoding : utf-8 -*-

control 'V-63343' do
  title "Windows 10 must employ automated mechanisms to determine the state of
        system components with regard to flaw remediation using the following
        frequency: continuously, where HBSS is used; 30 days, for any additional
        internal network scans not covered by HBSS; and annually, for external scans by
        Computer Network Defense Service Provider (CNDSP)."
  desc  "An approved tool for continuous network scanning must be installed and
        configured to run.

        Without the use of automated mechanisms to scan for security flaws on a
        continuous and/or periodic basis, the operating system or other system
        components may remain vulnerable to the exploits presented by undetected
        software flaws.

        To support this requirement, the operating system may have an integrated
        solution incorporating continuous scanning using HBSS and periodic scanning
        using other tools, as specified in the requirement."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'WN10-00-000025'
  tag gid: 'V-63343'
  tag rid: 'SV-77833r2_rule'
  tag stig_id: 'WN10-00-000025'
  tag fix_id: 'F-100903r1_fix'
  tag cci: ['CCI-001233']
  tag nist: ['SI-2 (2)', 'Rev_4']
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

  desc "check", "Verify DoD approved HBSS software is installed, configured, and
        properly operating. Ask the operator to document the HBSS software installation
        and configuration.

        If the operator is not able to provide a documented configuration for an
        installed HBSS or if the HBSS software is not properly configured, maintained,
        or used, this is a finding."

  desc "fix", "Install DoD approved HBSS software and ensure it is operating
        continuously."

  describe "A manual review is required to ensure the operating system employs automated mechanisms to determine the
  state of system components with regard to flaw remediation using the following
  frequency: continuously, where HBSS is used; 30 days, for any additional
  internal network scans not covered by HBSS; and annually, for external scans by
  Computer Network Defense Service Provider (CNDSP)." do
    skip 'A manual review is required to ensure the operating system employs automated mechanisms to determine the
  state of system components with regard to flaw remediation using the following
  frequency: continuously, where HBSS is used; 30 days, for any additional
  internal network scans not covered by HBSS; and annually, for external scans by
  Computer Network Defense Service Provider (CNDSP).'
  end
end

