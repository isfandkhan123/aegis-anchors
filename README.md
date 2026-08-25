# aegis-anchors — public governance anchors & portable decision proofs

This repository is the **public commitment surface** for the Aegis governance ledger. It holds two kinds of artifact:

1. **Anchor releases** — each GitHub Release carries a signed `anchor.json` committing a Merkle **checkpoint root** over the ledger's governed-decision chain, plus its Ed25519 signature (`anchor.sig`), the signing public key (`public.key`), and the full verification-key registry (`verification_keys.json`).
2. **Portable decision proofs** (`proofs/*.json`) — self-contained bundles that let anyone independently verify that **one specific governed decision** is included in a publicly anchored, immutable checkpoint, with **no access to Aegis, its database, its network, or any private key**.

> Anchoring makes later alteration or deletion of these records **detectable, not impossible**. What is published here is what a stranger can check.

---

## Verify a decision proof yourself (no Aegis access required)

```bash
# 1. a clean directory, nothing from Aegis
mkdir aegis-verify && cd aegis-verify

# 2. the self-contained verifier (stdlib + `cryptography` only)
curl -sO https://raw.githubusercontent.com/isfandkhan123/aegis-anchors/main/verify_decision_proof.py
python3 -m pip install --quiet cryptography

# 3. the two published proof fixtures
curl -sO https://raw.githubusercontent.com/isfandkhan123/aegis-anchors/main/proofs/aegis_decision_proof_v1__aea76ef5.json
curl -sO https://raw.githubusercontent.com/isfandkhan123/aegis-anchors/main/proofs/aegis_decision_proof_v1__51bb45c0.json

# 4. verify — each prints its layers and exits 0 on STRICT VERIFICATION PASS
python3 verify_decision_proof.py aegis_decision_proof_v1__aea76ef5.json
python3 verify_decision_proof.py aegis_decision_proof_v1__51bb45c0.json
```

Each bundle is **self-contained**: it embeds the decision, its signature, the Merkle inclusion path, the checkpoint, and the anchor artifacts (`anchor.json`, `anchor.sig`, `public.key`, `verification_keys.json`) — so the verifier needs nothing else. The same anchor artifacts are independently published as assets on the anchor release named inside each bundle (`anchor.release_tag`), if you wish to cross-check.

### What the verifier proves, layer by layer

```
DECISION HASH          recompute event_hash from the disclosed decision fields
DECISION SIGNATURE     Ed25519 over decision_id|envelope_hash, key resolved by key_id from the registry
POLICY (SET) COMMITMENT the signed decision commits to a policy hash (see "Policy provenance" below)
MERKLE INCLUSION       event_hash is the leaf; the path folds to the checkpoint root
CHECKPOINT ROOT        inclusion root == checkpoint root == the anchored root in anchor.json
ANCHOR SIGNATURE       Ed25519 over the exact anchor.json bytes
REGISTERED KEY         both keys resolve to the published registry; the anchor key is active_signing
```

and reports three **independent** axes:

```
CRYPTOGRAPHIC INTEGRITY   the record and its anchoring are sound
POLICY PROVENANCE         what governed the decision is committed (see below)
STRICT VERIFICATION       both of the above
```

A layer that cannot be checked **FAILs** — a proof that cannot be verified is not a proof.

### Optional: POLICY CONTENT MATCH
For a `decision_envelope_v2` proof you may additionally supply the exact policy definition an auditor holds separately:

```bash
python3 verify_decision_proof.py aegis_decision_proof_v1__51bb45c0.json --policy-def=effective_policy_set.json
```

`POLICY CONTENT MATCH PASS` appears **only** when a supplied definition canonicalizes to the committed `policy_set_hash`; otherwise it is `SKIPPED` and is **never** promoted to PASS. The policy definitions are **not published here** (see "Policy provenance" and "Durability limitation"), so in a public-only run this layer is correctly `SKIPPED`.

---

## The published fixtures

| | fixture | schema | signing key | what its policy layer proves |
|---|---|---|---|---|
| **V1** | `proofs/aegis_decision_proof_v1__aea76ef5.json` | `decision_envelope_v1` | `ed25519_primary_v1` (verify-only) | `LEGACY POLICY COMMITMENT` — a genuine registered adapter-policy hash |
| **V2** | `proofs/aegis_decision_proof_v1__51bb45c0.json` | `decision_envelope_v2` | `ed25519_primary_v2` (active) | `POLICY SET COMMITMENT` — the complete ordered effective policy set |

Both are real governed decisions (benign operational/dev checks), both are leaves in the immutable checkpoint `5805cf79-750d-45f7-accb-c028b9736581` (root `7b40cc5b…`), anchored at release `anchor-5805cf79-750d-45f7-accb-c028b9736581-2026-08-25`.

---

## Eras — four independent boundaries

These are **distinct** and must not be conflated.

### 1. Historical anchor era (pre proof-capability)
Historical anchor **release artifacts** (`anchor.json` + `anchor.sig`) remain **valid signed commitments** to their checkpoint roots. However, the pre-proof-capability daily checkpoint **database rows** were *mutable working records*, upserted per org-day, and many were subsequently recomputed. Measured finding: **11 of 16 sampled pre-proof-capability anchor rows had drifted** — the checkpoint row's current root no longer equals the root in its own signed public release. (This is the measured sample; it is not generalized beyond it.)

Consequence:
- **The signed public release artifact is the durable historical commitment** for those anchors.
- **Historical per-record membership cannot be independently reconstructed** where a leaf snapshot was never retained. Those anchors attest to a *moment*, not to a reconstructible *membership*.

### 2. Proof-capability era
First proof-capable immutable public checkpoint: **`df2e36d0-fe3b-467e-a34d-a4866b398721`** (2026-08-25). From this era onward, public anchor checkpoints are **immutable and snapshot-backed**: the exact ordered leaf population is frozen and retained, so **stable per-record Merkle inclusion proofs** (like the fixtures above) are possible and reproduce the anchored root regardless of later ledger writes.

### 3. Signing-key era
- `ed25519_primary_v1` — **verify-only**, retired from signing at **2026-08-22T14:50 UTC**. It remains permanently valid for verifying the records it signed.
- `ed25519_primary_v2` — **active-signing** since the rotation.

Both public keys, with their status and provenance notes, are published in `verification_keys.json` on every release. **This key rotation is independent of the decision-envelope schema below** — a "v2 key" is not the same thing as `decision_envelope_v2`.

### 4. Decision-envelope policy-provenance era
Decisions are now signed under **`decision_envelope_v2`**. A v2 envelope commits to the **complete, ordered effective policy set** that governed the decision via `policy_set_hash` (SHA-256 of the canonical set — global guards in their governed order, then adapter rules; evaluation is first-match, so **order is part of the commitment**), while keeping the full policy **definition private**.

Two claims, kept strictly separate:
- **`POLICY SET COMMITMENT PASS`** — the signed decision **commits to `policy_set_hash` X** over the complete effective set. This is what a public-only proof establishes.
- **`POLICY CONTENT MATCH PASS`** — a separately supplied policy definition **canonicalizes to X**. This is a *stronger, optional* result and requires the auditor to already possess the definition.

The first does **not** imply the second.

**Legacy semantics.** For historical `decision_envelope_v1` records, a genuine registered `policy_hash` has **narrower** meaning: it commits to a single **registered adapter policy**, and does **not** imply commitment to the complete effective global + adapter set. It renders as `LEGACY POLICY COMMITMENT`.

**Provenance gap, not invalidity.** A number of historical records carry `policy_hash` as the literal string `"unregistered_policy"` — they name no policy commitment. These are a **policy-provenance gap**, not cryptographically invalid records: such a record may still have a valid event hash, a valid Ed25519 signature, valid Merkle inclusion, and a valid anchor. The verifier reports them as `LEGACY POLICY COMMITMENT FAIL` while its `CRYPTOGRAPHIC INTEGRITY` axis can still PASS. `decision_envelope_v2` structurally prevents any *new* record from carrying that literal.

---

## Privacy — what a portable proof reveals

A portable decision proof discloses:
- the **subject decision** it is a proof for (its own fields and target);
- its **signature and key metadata** (`key_id`, the public key, the Ed25519 signature);
- its **policy commitment** (`policy_set_hash` / legacy `policy_hash`);
- the **opaque Merkle sibling commitments** along its inclusion path (hashes, not content);
- the **leaf's position** in the checkpoint;
- **information about the checkpoint/tree size.** Concretely: a proof carries a path of **~15 sibling hashes against a 22,023-leaf checkpoint**, which tells a reader the ledger holds **roughly twenty-two thousand governed decisions**. This is the accepted, intentional trade.

A proof does **not** disclose any neighboring decision's payload, nor the governing policy rule tree.

---

## Durability limitation (stated plainly)

The private, content-addressed **policy-set snapshots** (the definitions behind each `policy_set_hash`) currently live on a **single production volume with no demonstrated independent or offsite backup**. Therefore:
- the **public policy commitment remains cryptographically valid even if that disk is lost** — the anchored `policy_set_hash` and the checkpoint roots are durable and public;
- but a future **`POLICY CONTENT MATCH` may become impossible** if the corresponding private policy definition is lost and exists nowhere else.

Policy-definition recoverability is **not** claimed to be durable/redundant until such a backup exists. This does **not** affect the public proof gate, because public policy-**content** disclosure is intentionally **not** required — a public proof establishes `POLICY SET COMMITMENT`, not `POLICY CONTENT MATCH`.

---

## Tamper check (recommended)

Copy a bundle, corrupt one field, and confirm the verifier rejects it:

```bash
cp aegis_decision_proof_v1__51bb45c0.json tampered.json
python3 - <<'PY'
import json
b=json.load(open("tampered.json"))
b["decision"]["payload"]=b["decision"]["payload"].replace("aegis","AEGIS",1)  # change the signed content
json.dump(b,open("tampered.json","w"))
PY
python3 verify_decision_proof.py tampered.json   # -> DECISION HASH FAIL, STRICT VERIFICATION FAILED, exit 1
```

---

*What was removed from earlier documentation because it never existed or no longer applies: a per-record `ledger-batch.jsonl` file; the `merkle_root`/`ledger_version`/`environment` field names; the `merkletools` verification recipe; and the `anchor-test-g46-2026-05-11` example tag. None of those describe what this repository actually publishes.*
