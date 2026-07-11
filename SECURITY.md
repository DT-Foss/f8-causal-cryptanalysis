# Security policy

## Scope

F8-Causal is cryptanalysis research software. Its reference implementations
prioritize inspectable round state and deterministic experiments; they are not
production cryptographic implementations and must not protect real data.

Security-relevant reports include:

- a primitive or vector error that invalidates a retained result;
- a Reader/parser bug that accepts a digest-mismatched or malformed `.causal`
  artifact;
- command execution or path traversal from untrusted artifact input;
- a secret or private path committed to the public repository;
- a new practical vulnerability in a deployed primitive derived from these
  methods.

Scientific disagreements about interpretation can use a public issue with an
artifact hash and reproduction command. Potentially exploitable vulnerabilities
or accidental secret disclosure should be reported privately to **David Tom
Foss** at `david@foss.com.de` before public discussion.

## Report contents

Include the affected commit, file or artifact hash, platform, minimal command,
observed output, expected invariant, and whether the issue changes a stated
attack model or recovered object. Do not include third-party secret keys,
private conference correspondence, or unpublished personal data.

## Supported version

Security and integrity fixes target the current `main` branch and the latest
GitHub release. Historical result files remain immutable; corrections are added
as new artifacts and linked from the claim ledger.
