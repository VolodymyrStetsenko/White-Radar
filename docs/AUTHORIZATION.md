# Authorization and responsible disclosure

This document is an operational control, not legal advice.

## Required authorization record

Before any protocol-specific security research, retain a dated record containing:

- the legal owner or authorized representative;
- exact chain IDs, contract addresses, repositories, branches, and APIs in scope;
- permitted techniques and explicitly prohibited actions;
- testing window and rate limits;
- whether mainnet interaction is permitted;
- asset-handling rules;
- emergency contacts and an escalation path;
- confidentiality and disclosure deadlines;
- reward terms, if any;
- written acceptance by both parties.

A company registration, public profile, self-identification as a whitehat, or promise to return
assets does not authorize access or asset movement.

## White Radar operating modes

| Mode | Permitted use | Default |
|---|---|---|
| Public intelligence | Read public confirmed blocks and public verification metadata | Yes |
| Authorized watchlist | Monitor owned or explicitly scoped contracts and deployers | Yes |
| Pending watch | Observe metadata sent to explicitly scoped destinations | Off |
| Fork simulation | Separate controlled environment under written scope | Not implemented |
| Transaction execution | Requires separate reviewed system and human authorization | Not implemented |

## No automatic reward entitlement

There is no universal rule granting a researcher 10% of funds associated with an incident. A reward
exists only when a bug-bounty policy, competition rules, contract, or later settlement grants it.
Assume no entitlement until the applicable written terms say otherwise.

## Disclosure workflow

1. Stop active investigation when impact is plausible.
2. Preserve hashes, timestamps, addresses, blocks, and minimal reproduction evidence.
3. Re-check the published scope and prohibited actions.
4. Contact the official private security channel.
5. Share the minimum information needed to validate and mitigate.
6. Do not publish an unpatched critical issue.
7. Do not demand payment as a condition for returning or withholding assets or information.
8. Coordinate publication only after remediation and the agreed disclosure period.

## UK context

The [Crown Prosecution Service Computer Misuse Act guidance](https://www.cps.gov.uk/prosecution-guidance/computer-misuse-act)
describes authorization and knowledge of unauthorized access as central considerations. Operators
should obtain qualified legal advice for their exact service, jurisdiction, contracts, insurance,
and incident-response model before offering live intervention.
