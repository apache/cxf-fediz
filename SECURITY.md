# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.7.x   | :white_check_mark: |
| 1.6.x   | :white_check_mark: |
| < 1.6.x | :x:                |

## Reporting a Vulnerability

For information on how to report a new security problem please see [here](https://www.apache.org/security/).
Our existing security advisories are published [here](http://cxf.apache.org/security-advisories.html).

## Threat Model

What Fediz treats as in scope and out of scope, the security properties it
provides and disclaims (RP token validation: signature, audience, conditions,
replay, anti-signature-wrapping; IdP issuance and reply-URL validation), the
adversary model, and how inbound reports and tool/AI findings are triaged are
documented in [THREAT_MODEL.md](./THREAT_MODEL.md). Reporters and triagers
should consult it alongside this policy.
