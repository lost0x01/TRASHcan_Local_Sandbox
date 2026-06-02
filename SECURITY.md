# Security Policy

Do not open issues or pull requests containing live malware, weaponized payloads, private victim data, credentials, or sensitive infrastructure details.

## Reporting Security Issues

Report security issues privately to the repository maintainer. Include:

- A concise description of the issue
- Affected component
- Reproduction steps using benign artifacts when possible
- Suggested mitigation

## Malware Handling Rules

- Never commit malware samples or run artifacts.
- Never upload `.sample`, `.exe`, `.dll`, `.pcapng`, `.evtx`, memory dumps, or password-protected malware archives.
- Keep detonation VMs isolated on host-only networking.
- Scrub reports before publishing.

