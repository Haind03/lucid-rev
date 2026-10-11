# Security Policy

## Intended use

`lucid` is a static analysis tool for authorized research, CTFs, education and
responsible disclosure. Only analyze binaries you are permitted to examine.
`lucid` never executes the input binary in Milestone 1.

## Reporting a vulnerability in lucid

If you find a bug in `lucid` itself that could be triggered by a crafted input
file (e.g. a crash, hang or excessive memory use when parsing), please open a
private security advisory on GitHub
(**Security → Report a vulnerability**) rather than a public issue. Include the
lucid version, a minimal reproducer and the observed behaviour.
