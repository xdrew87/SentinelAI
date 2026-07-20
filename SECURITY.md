# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅ Yes    |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in SentinelAI, report it responsibly:

1. **Email:** Open a private security advisory via GitHub →  
   [https://github.com/xdrew87/SentinelAI/security/advisories/new](https://github.com/xdrew87/SentinelAI/security/advisories/new)

2. Include:
   - A clear description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

3. You will receive a response within **72 hours**.

## Security Considerations

- API keys and secrets are stored encrypted using the `cryptography` library — never in plain text
- The application does not make outbound network requests except to configured AI providers and threat intel feeds
- All database access is parameterized (no raw string interpolation in SQL queries)
- Crash logs are stored locally only and never transmitted

## Scope

The following are **in scope** for vulnerability reports:

- Authentication or secret storage bypass
- SQL injection or arbitrary code execution
- Insecure deserialization
- Path traversal in file analysis modules

The following are **out of scope**:

- Vulnerabilities in third-party dependencies (report those upstream)
- Social engineering attacks
- Issues requiring physical access to the machine
