# Microsoft Windows 10 Security Technical Implementation Guide
This InSpec Profile was created to facilitate testing and auditing of `Microsoft Windows 10`
infrastructure and applications when validating compliancy with [Department of Defense (DoD) STIG](https://public.cyber.mil/stigs/)
requirements.

- Profile Version: **3.2.0**
- Benchmark Date: **15 Nov 2024**
- Benchmark Version: **Version 3 Release 2 (V3R2)**


This profile was developed to reduce the time it takes to perform a security checks based upon the
STIG Guidance from the Defense Information Systems Agency (DISA) in partnership between the DISA Services Directorate (SD) and the DISA Risk Management Executive (RME) office.

The results of a profile run will provide information needed to support an Authority to Operate (ATO)
decision for the applicable technology.

The Microsoft Windows 10 STIG Profile uses the [InSpec](https://github.com/inspec/inspec)
open-source compliance validation language to support automation of the required compliance, security
and policy testing for Assessment and Authorization (A&A) and Authority to Operate (ATO) decisions
and Continuous Authority to Operate (cATO) processes.

Table of Contents
=================
- [Microsoft Windows 10 Security Technical Implementation Guide](#microsoft-windows-10-security-technical-implementation-guide)
- [Table of Contents](#table-of-contents)
  - [Benchmark Information](#benchmark-information)
  - [Getting Started](#getting-started)
    - [InSpec (CINC-auditor) setup](#inspec-cinc-auditor-setup)
    - [Intended Usage](#intended-usage)
    - [Tailoring to Your Environment](#tailoring-to-your-environment)
      - [Example of tailoring Inputs *While Still Complying* with the security guidance document for the profile:](#example-of-tailoring-inputs-while-still-complying-with-the-security-guidance-document-for-the-profile)
      - [Profile minimal inputs requirement](#profile-minimal-inputs-requirement)
      - [Using Customized Inputs](#using-customized-inputs)
    - [Testing the Profile Controls](#testing-the-profile-controls)
      - [Requirements](#requirements)
      - [Testing Commands](#testing-commands)
  - [Running the Profile](#running-the-profile)
    - [Directly from Github](#directly-from-github)
    - [Using a local Archive copy](#using-a-local-archive-copy)
  - [Different Run Options](#different-run-options)
  - [Using Heimdall for Viewing Test Results](#using-heimdall-for-viewing-test-results)
  - [Authors](#authors)
    - [Developers](#developers)
    - [Special Thanks](#special-thanks)
  - [NOTICE](#notice)
  - [NOTICE](#notice-1)
  - [NOTICE](#notice-2)
  - [NOTICE](#notice-3)

## Benchmark Information
The DISA RME and DISA SD Office, along with their vendor partners, create and maintain a set of Security Technical Implementation Guides for applications, computer systems and networks
connected to the Department of Defense (DoD). These guidelines are the primary security standards
used by the DoD agencies. In addition to defining security guidelines, the STIGs also stipulate
how security training should proceed and when security checks should occur. Organizations must
stay compliant with these guidelines or they risk having their access to the DoD terminated.

Requirements associated with the Microsoft Windows 10 STIG are derived from the
[Security Requirements Guides](https://csrc.nist.gov/glossary/term/security_requirements_guide)
and align to the [National Institute of Standards and Technology](https://www.nist.gov/) (NIST)
[Special Publication (SP) 800-53](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/800-53)
Security Controls, [DoD Control Correlation Identifier](https://public.cyber.mil/stigs/cci/) and related standards.

The Microsoft Windows 10 STIG profile checks were developed to provide technical implementation
validation to the defined DoD requirements, the guidance can provide insight for any organizations wishing
to enhance their security posture and can be tailored easily for use in your organization.

[top](#table-of-contents)
## Getting Started  
### InSpec (CINC-auditor) setup
For maximum flexibility/accessibility `cinc-auditor`, the open-source packaged binary version of Chef InSpec should be used,
compiled by the CINC (CINC Is Not Chef) project in coordination with Chef using Chef's always-open-source InSpec source code.
For more information see [CINC Home](https://cinc.sh/)

It is intended and recommended that CINC-auditor and this profile executed from a __"runner"__ host
(such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop)
against the target. This can be any Unix/Linux/MacOS or Windows runner host, with access to the Internet.

> [!TIP]
> **For the best security of the runner, always install on the runner the latest version of CINC-auditor and any other supporting language components.**

To install CINC-auditor on a UNIX/Linux/MacOS platform use the following command:
```bash
curl -L https://omnitruck.cinc.sh/install.sh | sudo bash -s -- -P cinc-auditor
```

To install CINC-auditor on a Windows platform (Powershell) use the following command:
```powershell
. { iwr -useb https://omnitruck.cinc.sh/install.ps1 } | iex; install -project cinc-auditor
```

To confirm successful install of cinc-auditor:
```
cinc-auditor -v
```

Latest versions and other installation options are available at [CINC Auditor](https://cinc.sh/start/auditor/) site.

[top](#table-of-contents)
### Intended Usage
1. The latest `released` version of the profile is intended for use in A&A testing, as well as
    providing formal results to Authorizing Officials and Identity and Access Management (IAM)s.
    Please use the `released` versions of the profile in these types of workflows. 

2. The `main` branch is a development branch that will become the next release of the profile.
    The `main` branch is intended for use in _developing and testing_ merge requests for the next
    release of the profile, and _is not intended_ be used for formal and ongoing testing on systems.

[top](#table-of-contents)
### Tailoring to Your Environment
This profile uses InSpec Inputs to provide flexibility during testing. Inputs allow for
customizing the behavior of Chef InSpec profiles.

InSpec Inputs are defined in the `inspec.yml` file. The `inputs` configured in this
file are **profile definitions and defaults for the profile** extracted from the profile
guidances and contain metadata that describe the profile, and shouldn't be modified.

InSpec provides several methods for customizing profile behaviors at run-time that does not require
modifying the `inspec.yml` file itself (see [Using Customized Inputs](#using-customized-inputs)).

The following inputs are permitted to be configured in an inputs `.yml` file (often named inputs.yml)
for the profile to run correctly on a specific environment, while still complying with the security
guidance document intent. This is important to prevent confusion when test results are passed downstream
to different stakeholders under the *security guidance name used by this profile repository*

For changes beyond the inputs cited in this section, users can create an *organizationally-named overlay repository*.
For more information on developing overlays, reference the [MITRE SAF Training](https://mitre-saf-training.netlify.app/courses/beginner/10.html)

#### Example of tailoring Inputs *While Still Complying* with the security guidance document for the profile:

```yaml
  # This file specifies the attributes for the configurable controls
  # used by the Microsoft Windows 10 STIG profile.

  # Disable controls that are known to consistently have long run times
  disable_slow_controls: [true or false]

  # A unique list of administrative users
  admins_list: [admin1, admin2, admin3]

  # List of configuration files for the specific system
  logging_conf_files: [
    <dir-path-1>/*.conf
    <dir-path-2>/*.conf
  ]
  
  ...
```

> [!NOTE]
>Inputs are variables that are referenced by control(s) in the profile that implement them.
 They are declared (defined) and given a default value in the `inspec.yml` file. 

#### Profile minimal inputs requirement
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. 

```yaml
  - set to either the string "true" or "false"
  sensitive_system: false

  - add your usernames as needed
  backup_operators: (NULL)

  - add your usernames as needed
  administrators: (NULL)

  - add your usernames as needed
  hyper_v_admin: (NULL)

  - add your AV Software Product to this list
  av_approved_software: <List of AV Software>
```

#### Using Customized Inputs
Customized inputs may be used at the CLI by providing an input file or a flag at execution time.

1. Using the `--input` flag
  
    Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input disable_slow_controls=true`

2. Using the `--input-file` flag.
    
    Example: `[inspec or cinc-auditor] exec <my-profile.tar.gz> --input-file=<my_inputs_file.yml>`

>[!TIP]
> For additional information about `input` file examples reference the [MITRE SAF Training](https://mitre.github.io/saf-training/courses/beginner/06.html#input-file-example)

Chef InSpec Resources:
- [InSpec Profile Documentation](https://docs.chef.io/inspec/profiles/).
- [InSpec Inputs](https://docs.chef.io/inspec/profiles/inputs/).
- [inspec.yml](https://docs.chef.io/inspec/profiles/inspec_yml/).


[top](#table-of-contents)
### Testing the Profile Controls
The Gemfile provided contains all the necessary ruby dependencies for checking the profile controls.
#### Requirements
All action are conducted using `ruby` (gemstone/programming language). Currently `inspec` 
commands have been tested with ruby version 3.1.2. A higher version of ruby is not guaranteed to
provide the expected results. Any modern distribution of Ruby comes with Bundler preinstalled by default.

Install ruby based on the OS being used, see [Installing Ruby](https://www.ruby-lang.org/en/documentation/installation/)

After installing `ruby` install the necessary dependencies by invoking the bundler command
(must be in the same directory where the Gemfile is located):
```bash
bundle install
```

#### Testing Commands

Linting and validating controls:
```bash
  bundle exec rake [inspec or cinc-auditor]:check # Validate the InSpec Profile
  bundle exec rake lint                           # Run RuboCop Linter
  bundle exec rake lint:auto_correct              # Autocorrect RuboCop offenses (only when it's safe)
  bundle exec rake pre_commit_checks              # Pre-commit checks
```

Ensure the controls are ready to be committed into the repo:
```bash
  bundle exec rake pre_commit_checks
```


[top](#table-of-contents)
## Running the Profile
### Directly from Github
This option is best used when network connectivity is available and policies permit
access to the hosting repository.

```bash
# Using `ssh` transport
bundle exec [inspec or cinc-auditor] exec https://github.com/mitre/microsoft-windows-10-stig-baseline/archive/main.tar.gz --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec [inspec or cinc-auditor] exec https://github.com/mitre/microsoft-windows-10-stig-baseline/archive/master.tar.gz --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

[top](#table-of-contents)
### Using a local Archive copy
If your runner is not always expected to have direct access to the profile's hosted location,
use the following steps to create an archive bundle of this overlay and all of its dependent tests:

Git is required to clone the InSpec profile using the instructions below.
Git can be downloaded from the [Git Web Site](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git).

When the **"runner"** host uses this profile overlay for the first time, follow these steps:

```bash
mkdir profiles
cd profiles
git clone https://github.com/mitre/microsoft-windows-10-stig-baseline.git
bundle exec [inspec or cinc-auditor] archive microsoft-windows-10-stig-baseline

# Using `ssh` transport
bundle exec [inspec or cinc-auditor] exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec [inspec or cinc-auditor] exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>    
```

For every successive run, follow these steps to always have the latest version of this profile baseline:

```bash
cd microsoft-windows-10-stig-baseline
git pull
cd ..
bundle exec [inspec or cinc-auditor] archive microsoft-windows-10-stig-baseline --overwrite

# Using `ssh` transport
bundle exec [inspec or cinc-auditor] exec <name of generated archive> --input-file=<your_inputs_file.yml> -t ssh://<hostname>:<port> --sudo --reporter=cli json:<your_results_file.json>

# Using `winrm` transport
bundle exec [inspec or cinc-auditor] exec <name of generated archive> --target winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>    
```

[top](#table-of-contents)
## Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

[top](#table-of-contents)
## Using Heimdall for Viewing Test Results
The JSON results output file can be loaded into **[Heimdall-Lite](https://heimdall-lite.mitre.org/)**
or **[Heimdall-Server](https://github.com/mitre/heimdall2)** for a user-interactive, graphical view of the profile scan results.

Heimdall-Lite is a `browser only` viewer that allows you to easily view your results directly and locally rendered in your browser.
Heimdall-Server is configured with a `data-services backend` allowing for data persistency to a database (PostgreSQL).
For more detail on feature capabilities see [Heimdall Features](https://github.com/mitre/heimdall2?tab=readme-ov-file#features)

Heimdall can **_export your results into a DISA Checklist (CKL) file_** for easily uploading into eMass using the `Heimdall Export` function.

Depending on your environment restrictions, the [SAF CLI](https://saf-cli.mitre.org) can be used to run a local docker instance
of Heimdall-Lite via the `saf view:heimdall` command.

Additionally both Heimdall applications can be deployed via docker, kubernetes, or the installation packages.

[top](#table-of-contents)
## Authors
[Defense Information Systems Agency (DISA)](https://www.disa.mil/)

[STIG support by DISA Risk Management Team and Cyber Exchange](https://public.cyber.mil/)

[MITRE Security Automation Framework Team](https://saf.mitre.org)

### Developers
* Aaron Lippold, Mitre - [aaronlippold](https://github.com/aaronlippold)
* Jared Burns, VMware.Inc - [burnsjared0415](https://github.com/burnsjared0415)

### Special Thanks
* Shivani Karikar, DIFZ - [karikarshivani](https://github.com/karikarshivani)

## NOTICE

© 2018-2025 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

## NOTICE 

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

## NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation.

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.

## NOTICE
[DISA STIGs are published by DISA IASE](https://public.cyber.mil/stigs/)
