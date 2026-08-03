# Incident Research Methodology

This methodology defines the minimum standard for a public incident reconstruction.
It is designed to make the work reproducible, reviewable, and explicit about uncertainty.

## 1. Intake

Record the earliest reliable notice of the incident and preserve the original source.
An alert is a lead, not evidence of root cause, impact, attribution, or completeness.

The intake record should include:

- first-seen timestamp and time zone;
- affected system and network;
- reported transaction, address, block, repository revision, or vendor advisory;
- the party making the claim;
- whether the affected team has acknowledged the event;
- immediate contradictions or unresolved claims.

## 2. Scope and revision

Before analysis, define the bounded scope:

- included networks, contracts, services, and time window;
- seed transactions or authoritative incident identifiers;
- pinned source-code revisions and deployment addresses;
- included and excluded evidence sources;
- provider limitations, pruning, missing traces, or unavailable off-chain data.

The scope may expand, but every expansion must be recorded.

## 3. Evidence classes

Every material statement should be classified as one of the following:

| Class | Meaning |
|---|---|
| **Observed** | Directly present in a primary artifact such as a transaction, receipt, trace, log, source revision, signed advisory, or vendor incident record |
| **Reproduced** | Recreated in an authorised local, forked, test, or simulation environment with documented steps and outputs |
| **Corroborated** | Supported by two or more independent sources whose evidence can be inspected |
| **Inferred** | A reasoned explanation supported by evidence but not directly proven by the available artifacts |
| **Reported** | Claimed by a named source but not independently verified in the case |
| **Unresolved** | Evidence is incomplete, contradictory, unavailable, or outside the defined scope |

Reported and inferred statements must not be written as observed facts.

## 4. Reconstruction workflow

### 4.1 Chronology

Build an ordered timeline covering:

- preparation and funding where observable;
- deployment, approvals, governance, or configuration changes;
- the first confirmed malicious or abnormal action;
- each material execution step;
- asset movement and conversion;
- protocol, operator, or responder actions;
- later recovery, freezing, negotiation, or disclosure events.

### 4.2 Execution

For each material transaction or system action, collect where available:

- transaction and receipt;
- block context;
- function and call tree;
- decoded inputs and events;
- state and storage changes;
- proxy and implementation context;
- reverted subcalls and failed attempts;
- source-code location tied to the relevant revision.

### 4.3 Impact

Separate:

- committed asset movement;
- reverted or attempted movement;
- protocol accounting impact;
- user exposure;
- reported loss;
- independently verified loss;
- recovered, frozen, or returned assets.

Do not treat token price, public claims, or address balances as self-explanatory.
State valuation time, source, and uncertainty.

### 4.4 Root cause

The root-cause section should distinguish:

1. the immediate failure condition;
2. the reachable execution path;
3. the violated invariant or trust assumption;
4. the enabling architectural, operational, or governance condition;
5. controls that existed but failed, were bypassed, or were absent.

A single vulnerable line is not necessarily the complete root cause.

### 4.5 Prevention

Recommendations should map to the reconstructed failure, not to generic security advice.
Where relevant, separate:

- code and invariant controls;
- deployment and upgrade controls;
- key, signer, and access controls;
- monitoring and response controls;
- user-interface and transaction-simulation controls;
- organisational and third-party controls.

## 5. Reproduction standard

A reproduction must state:

- environment and tool versions;
- pinned block, state, and code revision;
- commands or scripts used;
- assumptions and modified conditions;
- expected and actual results;
- whether the reproduction matches the original transaction exactly or only demonstrates the same failure class.

Simulation output is supporting evidence. It does not replace the mined transaction, original logs, or unavailable off-chain facts.

## 6. Attribution boundary

Public technical evidence can often support statements about addresses, contracts, infrastructure, execution, and asset flow.
It does not automatically prove human identity, intent, ownership, coordination, or legal responsibility.

Attribution requires independent off-chain corroboration and should be omitted when that standard is not met.

## 7. Review gate

Before publication, confirm that the case contains:

- a written scope and revision;
- source provenance;
- a coherent timeline;
- execution and impact evidence;
- a root-cause analysis tied to artifacts;
- explicit inference labels;
- limitations and unresolved questions;
- prevention controls tied to the failure;
- an integrity manifest for published artifacts.

If any central claim fails this gate, publish a preliminary note or wait. Do not fill gaps with confidence.

## 8. Corrections

Corrections must preserve the earlier public record where practical and state:

- what changed;
- why it changed;
- the new evidence;
- which conclusions are affected;
- the date and author of the update.
