### BIP110/RDTS activation change (hardfork)

RDTS no longer activates via versionbits signalling. As part of the hardfork,
RDTS rules are enforced for every block whose timestamp is in
[2026-09-01 00:00 UTC, 2028-09-01 00:00 UTC), replacing the prior versionbits
schedule, which the chain stall prevented from ever reaching activation at
height 965664. The expiry is approximately two years, a deliberate extension of
the previous ~1-year block-count schedule, to allow a permanent successor
design to be developed before RDTS ends.

The mandatory-signalling window at heights [961632, 963648) is unchanged for
blocks whose timestamps precede the fork.

There is no forced migration of funds: inputs spending coins created before
the fork remain valid under pre-RDTS script rules (grandfathering). Note such
spends are not relayed by policy and require direct miner submission.
