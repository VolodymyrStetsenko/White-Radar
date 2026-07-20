# Repository privacy

The repository contains defensive monitoring source code only. `.env`, `watchlist.toml`, databases,
logs, and local configuration are ignored. A public repository can support portfolio evidence and
independent review, but it also reveals the architecture and detection rules.

Use a private repository when the code, client names, watchlist, deployment model, or operational
thresholds are confidential.

## Make the GitHub repository private

1. Open the repository on GitHub.
2. Select **Settings**.
3. Under **General**, scroll to **Danger Zone**.
4. Select **Change repository visibility**.
5. Choose **Make private** and complete GitHub's confirmation.
6. Review collaborators, deploy keys, GitHub Apps, Actions secrets, and branch access afterward.

Official instructions: [Setting repository visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility).

Changing a public repository to private does not retract copies that were already cloned, cached,
forked, or otherwise obtained while it was public. Rotate any credential that was ever exposed;
repository visibility is not credential remediation.

## Access model

A private repository is visible to its owner and explicitly authorized GitHub collaborators or
installed applications. An external assistant is not a GitHub collaborator; continued repository
access depends on the GitHub connector permissions granted by the owner.
