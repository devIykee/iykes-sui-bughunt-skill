---
name: iykes-sui-bughunt-skill
description: >-
  End-to-end Sui Move bug-hunting playbook (researcher: deviykee). Invoke to hunt
  vulnerabilities in a Sui Move package or DeFi protocol and turn a finding into a
  responsible, paid disclosure. Fill the INTAKE block, then run the steps in order.
  Verification is local only: `sui move test`, a localnet, or read-only
  devInspect / dryRun against mainnet state. Never sign or execute a mainnet
  transaction. Be token-conservative. Maintain coverage.md incrementally and never
  imply a complete audit when coverage is low. Report every confirmed Low, Medium,
  or High at its real severity. Use when the user names a Sui target and says
  "hunt", "audit this", or "find bugs".
---

# Iyke's Sui Bughunt Skill

By **deviykee**. Same structure as the EVM skill (iykes-evm-bughunt-skill), rebuilt
for Sui's object model. Fill the INTAKE, then run the steps top to bottom.

### Core principle: proactive problem-solving

When you hit a blocker, find or build a way through. No source? Pull bytecode with
`sui client object <package_id>` / RPC `sui_getNormalizedMoveModulesByPackage` and
decompile with `revela` or Move disassembler. Missing tool? Install it
(`cargo install --locked --git https://github.com/MystenLabs/sui.git sui`). Rate
limited? Rotate public fullnodes. Document every workaround in `tools/`.

### Token budget

Shell first for facts (`sui client`, `curl` JSON-RPC, `rg`). One finding path at a
time until confirmed or killed. Chunk, do not dump: feed one module / one entry
function per adversarial question. Small models for greps, object listing, and test
runs; primary model for severity, root cause, and exploit design.

---

## Attack paths to explore FIRST (Sui Move)

Run every target against this checklist before anything else. For each, ask "can a
stranger reach this with a valid programmable transaction block using objects they
own or shared objects anyone can pass?" and write a one-line verdict (reachable /
blocked / N/A) into `coverage.md`. Chase reachable ones to a `sui move test` or
devInspect PoC. Skip none without a reason logged.

1. Fund draining - theft via flawed transfer, accounting, or authorization logic.
2. Shared object misuse - improper access control on shared objects enabling unauthorized mutation.
3. Capability leakage - a cap that gates access is exposed, returned by value, has `store`, or is transferable when it should not be.
4. Object ownership confusion - logic assumes the wrong model (owned vs shared vs immutable vs wrapped / dynamic field).
5. Unauthorized object transfer - missing checks let an attacker move objects they do not own (public_transfer on `store` objects).
6. Missing ability checks - `key`, `store`, `copy`, `drop` misuse allowing duplication, silent drops of hot potatoes, or free transfer.
7. Witness pattern bypass - one-time witness or witness type misused or forgeable; `public(package)` vs `public` exposure.
8. Malicious coin / object type - generic `T` not pinned, fake `Coin<T>` or `TreasuryCap<T>` passed where a real one is expected.
9. Arithmetic and logic errors - Move aborts on overflow but not on bad rounding; check rounding direction, u64 truncation after u128 math, off-by-one.
10. Oracle manipulation - flash-loan or thin-liquidity distortion, stale or single-source feeds (Pyth / Supra staleness and confidence).
11. Vault / share inflation - first depositor manipulates share price via direct donation.
12. Donation attacks - direct `Coin` / `Balance` join desyncs internal tracking from actual holdings.
13. Flash-loan attacks - hot-potato flash loans used to manipulate accounting or governance in one PTB.
14. Liquidation manipulation - manipulating price or health factor to trigger unfair liquidations.
15. Governance attacks - flash-loaned voting power, low-quorum exploitation, proposal griefing.
16. Signature and replay - missing nonce, missing chain identifier, replay across devnet/testnet/mainnet (ed25519 / secp256k1 verify in Move).
17. Upgrade vulnerabilities - unprotected `UpgradeCap`, broken version gating (`version` field not checked on shared objects), compatible-upgrade surprises.
18. Denial of service - blocking shared objects, unbounded vectors / tables iterated in one call, locking critical state.
19. Front-running and MEV - ordering exploitation on shared-object transactions under Sui consensus.
20. Insecure randomness - anything other than `sui::random` (epoch, timestamp, object ids); also `Random` used in a public non-entry function (test-and-abort).
21. Cross-chain bridge attacks - message replay, fake proof acceptance, signature bypass on destination.
22. Merkle proof manipulation - malformed or duplicate leaves, missing proof uniqueness checks.

---

## INTAKE - fill this in before running

```
PROJECT_NAME=
WEBSITE=
PACKAGE_IDS=            # every published package, incl. upgraded versions
SHARED_OBJECTS=         # pools, vaults, configs, registries
CAP_OBJECTS=            # AdminCap, UpgradeCap, TreasuryCap holders
PRODUCT_TYPE=           # AMM / CLMM / lending / vault / perps / launchpad / bridge / staking
SOURCE=                 # GitHub repo + commit, or "bytecode only"
TVL_AT_RISK=
BOUNTY_PROGRAM=         # URL or "none found"
SECURITY_CONTACT=       # quoted from their own site/docs/security.txt
HUNT_DIR=hunts/<project>
```

## Operating rules (non-negotiable)

1. Never sign or execute a mainnet transaction. Use `sui move test`, localnet, or
   `sui_devInspectTransactionBlock` / `sui_dryRunTransactionBlock` read-only.
2. Never touch live funds, never test third-party infra, never social engineer.
3. Honest severity. Kill your own finding before reporting it.
4. Private disclosure only, signed deviykee, plain human prose, no em dashes.
5. Keep a Low or Medium if it is a step toward a Critical; report every confirmed
   issue at its real severity.
6. Coverage tracking is mandatory.

## Coverage tracking (mandatory every hunt)

`coverage.md` in HUNT_DIR: modules opened, entry/public functions traced, the
attack-path checklist verdicts, % of modules covered, and an "Explicitly excluded"
section. Never imply a full audit when coverage is low.

## Tools

| Need | Command |
|---|---|
| Package modules | `curl -s $RPC -d '{"jsonrpc":"2.0","id":1,"method":"sui_getNormalizedMoveModulesByPackage","params":["<PKG>"]}'` |
| Object state | `sui client object <ID> --json` or `sui_getObject` with `showContent` |
| Dynamic fields | `suix_getDynamicFields` |
| Who owns caps | `sui_getObject` with `showOwner` on each cap |
| Upgrade history | `UpgradeCap` object + package `version`; check `suix_queryEvents` for `UpgradeEvent` |
| Decompile | `revela`, or `sui move disassemble` on fetched bytecode |
| Static checks | `sui move build --lint`, Move Prover where specs exist |
| PoC | `sui move test` with `test_scenario`; devInspect for live-state reads |

Public RPCs: `https://fullnode.mainnet.sui.io:443`, plus provider mirrors.

## STEP 1 - Ground truth (is this real, and where)

Confirm the project, the package IDs, and value at risk from on-chain balances in
shared objects, not marketing TVL.

## STEP 2 - Locate the core package(s)

Map every package ID including upgraded versions (`original_id` vs latest). Find
the repo via GitHub search on module names or package IDs. Note `Move.toml`
published-at addresses.

## STEP 3 - Verification gate + surface map

Does public source match on-chain bytecode? List every `public` and `entry`
function, every shared object they touch, and which caps gate them. Mark functions
that take `&mut` shared objects without a cap as the first surface to read.

## STEP 3.5 - Bytecode-only packages

Fetch normalized modules, decompile, and rebuild the surface map from signatures:
functions taking `&mut Pool` with no cap argument, functions returning caps or
`Balance`, generic `T` without a type check.

## STEP 4 - Auth triage (find the free win first)

For each privileged-looking function: is it gated by a cap passed by reference, by
`tx_context::sender` compared to a stored address, or by nothing? Can the cap be
obtained (public constructor, `store` ability, returned from a public function)?
Is `public(package)` used where `public` leaks it to every PTB?

## STEP 5 - Foundation map (before deep findings)

Write down the invariants: total shares vs pool balance, debt vs collateral,
version fields on shared objects, fee accrual. Note every place a `Balance` is
split, joined, or destroyed.

## STEP 5.5 - Multi-angle adversarial pass

Invent an impossible state (ragnarok method), then try to reach it with a single
PTB that chains public calls: flash loan, mutate, repay. PTBs let an attacker
compose up to 1,024 calls atomically, so treat every public function as composable
with every other.

## STEP 6 - Read with attack questions (by PRODUCT_TYPE)

AMM / CLMM: tick math rounding, fee growth overflow, swap with zero-amount edge.
Lending: oracle staleness, liquidation bonus rounding, interest index update order.
Vault: first-deposit inflation, donation via `balance::join`, share rounding.
Launchpad / bonding curve: price math rounding, migration step reachable early.
Staking: reward-per-share update before stake changes, epoch boundary off-by-one.
Bridge: message hash includes chain id and nonce, validator set update auth.

## STEP 6.5 - Bug-class detection playbook

Grep for: `public fun` returning caps or `Balance<`, `public_transfer` on sensitive
objects, generic `<T>` on deposit without `type_name` check, missing `version`
assert on shared objects, `clock::timestamp_ms` used as randomness, loops over
`vector` / `table` keyed by user input, `u128` math cast to `u64`, `abort` paths a
user can trigger to block others on a shared object.

## STEP 7 - Prove it locally (mandatory)

Write a `sui move test` using `test_scenario` that reproduces the bug with
attacker and victim addresses. For live-state magnitude, use devInspect against
mainnet objects read-only. Record the exact numbers.

## STEP 8 - Severity call (honest rubric)

Critical: stranger drains or permanently freezes user funds. High: theft or freeze
with realistic preconditions. Medium: loss bounded or needing unlikely conditions,
or temporary freeze. Low: footgun, griefing, no fund loss. Kill
temporary-vs-persistent conditions before calling severity.

## STEP 9 - Report (fill-in template)

```
# <Project> - <Severity>: <one-line title>
Researcher: deviykee
Status: proven with sui move test / devInspect. No mainnet transaction sent.

## What this means in plain language (read this first)
## Affected packages and objects (Sui mainnet)
## Summary
## Root cause
## Attack
## Impact
## Proof of concept
## Fix
## Disclosure & compensation
deviykee
```

## STEP 10 - Disclose and get paid

Send only fork/local-confirmed bugs to the team's verified official security
contact, quoted from their own site or security.txt. Email body in plain prose with
no markdown; attach the full report and PoC. Never threaten, never publish, never
condition the fix on payment.

## STEP 11 - Frontend security audit (always check)

**Run this step for every hunt, regardless of product type.** Frontend issues can
be as critical as Move bugs — especially **unauthenticated server / API /
database access** reachable from the dApp, plus exposed API keys that control
RPC access, sponsorship, or authentication.

### 11A. Bundle scrape (Sui-specific + secrets)

Scrape the dApp bundle for:
- leaked keys (Bearer, service-role, sponsor / gas-station keys, private keys)
- hardcoded package IDs that differ from the live ones
- PTB construction that passes user-controlled object IDs or coin types
- missing slippage or deadline arguments
- every API base URL, GraphQL endpoint, Firebase / Supabase config, webhook path

Save hits under `frontend-security/` (bundle extract, endpoint list, key greps).

### 11B. Unauthenticated server / database access (primary frontend hunt goal)

**When hunting a frontend, exposed secrets are one path. The other — and often
higher-impact — path is unauthenticated (or under-authenticated) access to the
project's backend, APIs, or database.** Treat this as a first-class objective of
Step 11, not an afterthought.

You are looking for ways a stranger (no session, no wallet signature, no admin
cookie) can:

1. **Read or write the database** — open Firebase / Supabase / Appwrite / Hasura
   rules, leaked service-role keys, GraphQL that accepts mutations without auth,
   REST that creates / updates / deletes rows without a check.
2. **Call privileged server endpoints** — `/admin`, `/internal`, `/debug`,
   webhooks with no shared-secret, unsigned cloud-function URLs, open CORS +
   cookie-less state-changing POSTs.
3. **Bypass auth on user actions** — IDOR (change `userId` / `address` /
   `suiAddress` in the request and hit another account), missing ownership
   checks on update/delete, unsigned "claim" / "payout" / "credit" APIs that
   trust a client-supplied address.
4. **Abuse storage / queues** — public S3 / GCS / R2 buckets writable by anyone,
   open Redis / Mongo endpoints, message queues that accept unauthenticated
   publish.
5. **Chain a frontend secret into server access** — a leaked Bearer / service key
   that unlocks (1)–(4). Rate-limit-only keys are usually Low; keys that mutate
   production data are High/Critical.

**How to hunt (read-only / non-destructive first):**
- From the bundle, list every API base URL, GraphQL endpoint, Firebase config,
  Supabase URL + `anon` / `service_role` key, and webhook path.
- For each write-shaped endpoint (`POST`/`PUT`/`PATCH`/`DELETE`, GraphQL
  mutation, Firebase `.set` / `.update`, Supabase `.insert` / `.upsert`):
  try the call **without** cookies, Authorization headers, or wallet signatures.
  Document status codes and whether the mutation stuck.
- Check Firebase / Supabase security rules if the project is public or the
  rules file ships in the bundle / repo. Look for `allow read, write: if true`
  and `service_role` used from the client.
- IDOR: replay a legitimate update with a different `id` / `suiAddress` /
  `userId`.
- Never dump production user data, never delete, never spam write volume. One
  inert prove-it row (or a dry-run that the server rejects after the auth check)
  is enough for the PoC. Prefer staging / the project's own test fixtures when
  available.

**Severity (honest):**
- Unauthenticated **write** that changes balances, credits, inventory, roles, or
  payouts → Critical / High (map to the program's payout table).
- Unauthenticated **read** of PII, private keys, or full DB dumps → High.
- Unauthenticated read of non-sensitive public-ish data, or write that only
  affects the attacker's own empty sandbox → Low / Informational.
- Exposed `anon` keys that are designed to be public (Supabase anon with tight
  RLS) are not findings unless RLS actually fails.

Record every tested endpoint in `frontend-security/api-auth-matrix.md`
(method, path, auth required?, stranger result, data impact). Failures to
mutate as a stranger go in the kill-log, not the findings table.

### 11C. Operating note

Frontend security is mandatory on every Sui hunt. Hardcoded API keys, bearer
tokens, leaked keypairs, and sponsor keys can be as critical as Move bugs. Also
hunt for unauthenticated (or under-authenticated) server, API, and database
access reachable from the frontend — open write endpoints, IDOR, and
misconfigured Firebase/Supabase/GraphQL are primary targets (see 11B).

## Appendix A - Sui cheat-sheet

- Abilities: `key` (object), `store` (wrappable and freely transferable), `copy`,
  `drop`. A hot potato has none, so it must be consumed in the same PTB.
- `transfer::transfer` is module-restricted; `public_transfer` works on any `store`
  object from any PTB.
- Shared objects are mutable by anyone who can call a function taking `&mut`; the
  function is the only guard.
- Upgrades keep old package versions callable unless shared objects carry a
  `version` field checked by every entry point.
- `sui::random` must be used from non-public `entry` functions to avoid
  test-and-abort.
