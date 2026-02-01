# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in AAPI, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email security concerns to: **security@aapi-project.org** (or create a private security advisory on GitHub)
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability within 7 days
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days
- **Disclosure**: We will coordinate disclosure timing with you

### Security Best Practices for Users

#### Production Deployment

1. **Enable Production Mode**
   ```rust
   let config = GatewayConfig::production();
   ```
   This enables:
   - Signature verification required
   - Capability verification required
   - Default-deny policy behavior

2. **Use HTTPS/TLS**
   - Always deploy behind a TLS-terminating proxy
   - Use valid certificates from trusted CAs

3. **Secure Database**
   - Use encrypted SQLite or PostgreSQL with TLS
   - Restrict database file permissions
   - Regular backups with encryption

4. **Network Security**
   - Deploy in a private network
   - Use firewall rules to restrict access
   - Consider VPN for remote access

5. **Key Management**
   - Rotate signing keys regularly
   - Store keys in secure key management systems
   - Never commit keys to version control

#### Adapter Security

1. **File Adapter**
   - Always configure a sandbox directory
   - Use restrictive file permissions
   - Monitor for path traversal attempts

2. **HTTP Adapter**
   - Whitelist allowed domains
   - Use request signing for external APIs
   - Implement rate limiting

#### Policy Configuration

1. **MetaRules Policies**
   - Start with default-deny
   - Explicitly allow required actions
   - Require approval for sensitive operations
   - Regular policy audits

2. **Capability Tokens**
   - Use short expiration times
   - Implement budget limits
   - Audit token usage

## Security Features

### Cryptographic Signing

- **Algorithm**: Ed25519 (EdDSA)
- **Key Size**: 256-bit
- **Hash**: SHA-256 for VĀKYA canonicalization

### Audit Trail

- Append-only evidence log
- Merkle tree for tamper detection
- Cryptographic receipts for all actions

### Policy Enforcement

- MetaRules policy engine
- Allow/Deny/PendingApproval decisions
- Capability-based access control

## Known Security Considerations

### Current Limitations

1. **Capability Token Enforcement**: Full token-based capability verification is pending implementation in the request schema
2. **Key Rotation**: Automated key rotation is not yet implemented
3. **Rate Limiting**: Built-in rate limiting is not yet implemented

### Recommended Mitigations

- Use external rate limiting (nginx, API gateway)
- Implement key rotation via operational procedures
- Monitor audit logs for anomalies

## Security Changelog

### v0.1.0 (Beta)
- Initial security implementation
- Ed25519 signature verification
- MetaRules policy enforcement
- Production mode with strict defaults
- File adapter sandboxing

## Acknowledgments

We thank the security researchers who help keep AAPI secure. Contributors will be acknowledged here (with permission).
