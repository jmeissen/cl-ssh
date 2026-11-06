# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through [GitHub private
vulnerability
reporting](https://github.com/jmeissen/cl-ssh/security/advisories/new). Please
only open a public issue after a fix or coordinated disclosure has been agreed.

Include the affected version or commit, a minimal reproduction, impact, and any
mitigation you have identified. I aim to resolve reports within seven days and
keep reporters informed during investigation.

## Supported versions

Essentially, the latest released version is supported and receives security
fixes. Additionally, the `master` branch is supported while the next release is
in development. Earlier release lines will not receive fixes because there will
only be one release line.

## Disclosure and fixes

We use coordinated disclosure. After confirming a report, maintainers will
develop and test a fix, coordinate a disclosure date where practical, and
publish a security-fix release and advisory. Active exploitation or urgent user
risk may require an accelerated release.

Security releases include a signed annotated tag, SHA-256 checksum, and the
applicable automated test, integration, fuzz, and secret-scan evidence.
