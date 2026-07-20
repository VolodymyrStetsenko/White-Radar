# Security policy

## Supported version

The latest release on the default branch receives security fixes.

## Reporting a vulnerability

Use a private GitHub Security Advisory for this repository. Do not open a public issue containing a
working exploit, credential, private client scope, or unpatched critical detail.

Include:

- affected version and commit;
- impact and required preconditions;
- minimal reproduction in a local or test environment;
- suggested mitigation;
- whether any secret or production data may have been exposed.

## Credentials

Never send API keys, bot tokens, wallet seed phrases, private keys, or `.env` files. If a credential
was committed, uploaded, pasted into a third-party system, or otherwise exposed, revoke it at the
provider and issue a replacement. Deleting the file or commit is not sufficient by itself.

## Scope

Security research against White Radar does not authorize testing any monitored protocol, RPC
provider, explorer, Telegram, GitHub, or other third party.
