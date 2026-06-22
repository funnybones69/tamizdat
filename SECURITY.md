# Security Policy

## Reporting vulnerabilities

Please report security issues privately to the repository owner. Do not include real profile URIs, short IDs, private keys, panel passwords, databases, certificates, or logs in public issues.

When reporting a bug, include:

- release version or commit hash;
- operating system and architecture;
- server/client command-line flags with secrets redacted;
- relevant log excerpts with secrets redacted;
- steps to reproduce.

## Deployment guidance

- Keep the admin panel private or protected by an additional authentication layer.
- Store `/etc/tamizdat/` backups encrypted.
- Rotate user profiles after leaks or device loss.
- Review firewall rules before exposing services to the Internet.
