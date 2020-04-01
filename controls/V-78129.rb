# -*- encoding : utf-8 -*-

control 'V-78129' do
  title "Administrative accounts must not be used with applications that access
        the Internet, such as web browsers, or with potential Internet sources, such as
        email."
  desc  "Using applications that access the Internet or have potential Internet
        sources using administrative privileges exposes a system to compromise. If a
        flaw in an application is exploited while running as a privileged user, the
        entire system could be compromised. Web browsers and email are common attack
        vectors for introducing malicious code and must not be run with an
        administrative account.

        Since administrative accounts may generally change or work around technical
        restrictions for running a web browser or other applications, it is essential
        that policy requires administrative accounts to not access the Internet or use
        applications, such as email.

        The policy should define specific exceptions for local service
        administration. These exceptions may include HTTP(S)-based tools that are used
        for the administration of the local system, services, or attached devices.

        Technical means such as application whitelisting can be used to enforce the
        policy to ensure compliance."
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'WN10-00-000240'
  tag gid: 'V-78129'
  tag rid: 'SV-92835r1_rule'
  tag stig_id: 'WN10-00-000240'
  tag fix_id: 'F-84851r1_fix'
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
  desc "check", "Determine whether administrative accounts are prevented from
      using applications that access the Internet, such as web browsers, or with
      potential Internet sources, such as email, except as necessary for local
      service administration.

      The organization must have a policy that prohibits administrative accounts from
      using applications that access the Internet, such as web browsers, or with
      potential Internet sources, such as email, except as necessary for local
      service administration. The policy should define specific exceptions for local
      service administration. These exceptions may include HTTP(S)-based tools that
      are used for the administration of the local system, services, or attached
      devices.

      Technical measures such as the removal of applications or application
      whitelisting must be used where feasible to prevent the use of applications
      that access the Internet.

      If accounts with administrative privileges are not prevented from using
      applications that access the Internet or with potential Internet sources, this
      is a finding."

  desc "fix", "Establish and enforce a policy that prohibits administrative
      accounts from using applications that access the Internet, such as web
      browsers, or with potential Internet sources, such as email. Define specific
      exceptions for local service administration. These exceptions may include
      HTTP(S)-based tools that are used for the administration of the local system,
      services, or attached devices.

      Implement technical measures where feasible such as removal of applications or
      use of application whitelisting to restrict the use of applications that can
      access the Internet."

  describe 'Establish and enforce a policy that prohibits administrative account from using applications that access the Internet' do
    skip 'Implement technical measures where feasible such as removal of application
   or use of application whitelisting to restrict the use of applications that can access Internet'
  end
end

