# Repository privacy

White Radar separates source code from operational data.

## Repository contents

The source repository contains:

- engine source;
- database schema;
- sanitized configuration examples;
- deployment templates;
- tests and CI;
- product and operations documentation.

The following paths are ignored and remain local:

- `.env`;
- `config.toml`;
- `watchlist.toml`;
- `policies.toml`;
- `data/`;
- `evidence/`;
- databases, WAL files, logs, reports, and exports.

## Visibility decision

A private repository is the default for proprietary detection logic, deployment topology, internal
roadmaps, or restricted client context.

A public repository can contain a sanitized engine, architecture, examples, and product
documentation. Operational policies, protocol inventory, real reports, provider topology,
thresholds, and incident runbooks should remain in a separate private repository or secret/data
store.

## GitHub privacy procedure

1. Open repository **Settings**.
2. Under **General**, open **Danger Zone**.
3. Select **Change repository visibility**.
4. Choose **Make private** and confirm.
5. Review collaborators, teams, deploy keys, installed GitHub Apps, Actions secrets, environments,
   branch protection, and rulesets.
6. Enable secret scanning and push protection where the account plan supports them.

Official instructions:
[Setting repository visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility).

## Credential handling

Repository visibility is not a credential-control mechanism. Any credential that appears in chat,
an issue, a log, an archive, a commit, or a public file must be revoked and replaced. Removing a
file or rewriting history does not invalidate the credential.

Use:

- repository/environment secrets for CI;
- a host environment file or secret manager for runtime;
- narrowly scoped credentials;
- independent production and development credentials;
- documented rotation and revocation.

## Public/private split

When maintaining both editions:

- keep separate repositories;
- copy only reviewed, sanitized changes into the public edition;
- do not use the private engine as a public Git submodule;
- run secret scanning on both staged changes and full history;
- keep screenshots and example reports redacted;
- maintain an inventory of installed apps and machine credentials.
