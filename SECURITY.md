# Security Policy

## Supported Versions

We support the latest two minor versions of `modelvet`. Security updates are backported to both versions as needed.

| Version | Supported          |
|---------|-------------------|
| 1.x     | ✓ (latest)        |
| 0.x     | ✗ (end-of-life)   |

## Reporting a vulnerability

If you discover a security vulnerability in `modelvet`, **do not open a public GitHub issue**. Instead, use GitHub's private vulnerability reporting:

1. Navigate to the [Security Advisories](https://github.com/t3bik/modelvet/security/advisories) tab.
2. Click **"Report a vulnerability"** and fill in the report form.
3. Include:
   - A clear description of the issue.
   - Steps to reproduce (if applicable).
   - The affected version(s).
   - Any references or proof-of-concept code.

**Response timeline:**
- We will acknowledge receipt within 48 hours.
- We will investigate and provide a status update within 7 days.
- We aim to release a patch within 30 days for Critical findings.
- You will be credited in the security advisory upon publication (unless you prefer to remain anonymous).

## Security Advisories

All resolved security issues are published in [GitHub Security Advisories](https://github.com/t3bik/modelvet/security/advisories).

## Scope

`modelvet` is a **static analysis tool** that reads file bytes and emits findings. It does **not**:
- Load or execute models.
- Parse untrusted Python code.
- Follow external references or network calls.
- Make decisions about whether to load a file (that is the caller's responsibility).

Security vulnerabilities in `modelvet` scope are:
- Panics on hostile input (crashes the scanner).
- Out-of-memory or unbounded allocation (DoS).
- False-negatives in detection (e.g., a malicious pickle not flagged).
- Incorrect or overly lenient bounds checking.

Out of scope:
- Security properties of the models themselves (e.g., training-data extraction, adversarial robustness).
- Decisions about whether to reject a finding (that is policy, not the tool's responsibility).
- Issues in dependencies (report directly to the maintainer of the affected dependency).

## Vulnerability Disclosure

We adhere to **responsible disclosure**. We will:
1. Investigate privately via the GitHub Security Advisory.
2. Prepare a fix and release a new version.
3. Publish the advisory and disclose the issue publicly.

We ask that you:
- Not disclose the vulnerability publicly until a fix is released.
- Allow us time to coordinate with maintainers of affected downstream projects.
- Provide a reasonable grace period (typically 90 days) before public disclosure.

## Contact

For questions or clarifications, contact the maintainers via the private advisory form.
