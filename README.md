# aegis-anchors.json is the canonical artifact. It contains:

- `merkle_root` - SHA-256 root of the decision record batch
- `record_count` — number of governed decisions in this batch
- `timestamp_utc` — anchor creation time (ISO 8601)
- `environment` — deployment environment identifier
- `ledger_version` — monotonically increasing ledger sequence number
- `previous_anchor` — reference to the preceding anchor (enabling chain verification)

The `ledger-batch.jsonl` file contains one JSON object per line, one per governed decision. Each record includes the decision type, policy version, agent identifier, and a SHA-256 hash of the full decision payload.

---

## How to Verify

Verification requires standard command-line tooling. No Aegis software, account, or access is needed.

### Prerequisites

```bash
# macOS
brew install openssl

# Debian / Ubuntu
apt install openssl

# Python
pip install merkletools
```

### Step 1 — Download the anchor artifacts

```bash
RELEASE_TAG="anchor-test-g46-2026-05-11"

gh release download "$RELEASE_TAG" \
  --repo isfandkhan123/aegis-anchors \
  --dir ./verify
```

Or download manually from the [releases page](https://github.com/isfandkhan123/aegis-anchors/releases).

### Step 2 — Verify the Ed25519 signature

```bash
cd verify

openssl pkeyutl \
  -verify \
  -pubin \
  -inkey public.key \
  -sigfile anchor.sig \
  -in anchor.json \
  -pkeyopt digest:sha256
```

Expected output: `Signature Verified Successfully`

### Step 3 — Verify the Merkle root

```python
import json, hashlib
from merkletools import MerkleTools

with open("ledger-batch.jsonl") as f:
    records = [line.strip() for line in f if line.strip()]

mt = MerkleTools(hash_type="sha256")
mt.add_leaf([hashlib.sha256(r.encode()).hexdigest() for r in records])
mt.make_tree()

computed_root = mt.get_merkle_root()

with open("anchor.json") as f:
    anchor = json.load(f)

assert computed_root == anchor["merkle_root"], \
    "Root mismatch — ledger may have been altered"
print(f"Merkle root verified: {computed_root}")
```

### Step 4 — Verify a specific decision record (optional)

```python
import json, hashlib
from merkletools import MerkleTools

with open("ledger-batch.jsonl") as f:
    records = [line.strip() for line in f if line.strip()]

record_index = 0  # replace with the index you want to verify
record_hash = hashlib.sha256(records[record_index].encode()).hexdigest()

mt = MerkleTools(hash_type="sha256")
mt.add_leaf([hashlib.sha256(r.encode()).hexdigest() for r in records])
mt.make_tree()

proof = mt.get_proof(record_index)
is_valid = mt.validate_proof(proof, record_hash, mt.get_merkle_root())
print(f"Record {record_index} inclusion proof: {'valid' if is_valid else 'invalid'}")
```

If any step fails, the anchor does not validate. The record cannot be trusted.

---

## What Aegis Is

Aegis is governance infrastructure for autonomous AI systems. It sits between an AI agent and the actions that agent is permitted to take, evaluating each request against a defined policy set and producing a signed, auditable record of every decision. The system is designed to operate at the latency requirements of production AI workloads, governance happens inline, not after the fact.

The core thesis is that AI governance cannot be a dashboard. Dashboards describe what happened; they do not constrain what can happen. Aegis is a control plane: policies are enforced at execution time, decisions are recorded at decision time, and the record is committed to an external anchor before the next batch begins. The result is a governance posture that can be audited by external parties without access to internal systems.

Aegis is built for operators who bear accountability for autonomous systems — organizations deploying AI agents in regulated industries, high-stakes enterprise workflows, or environments where the cost of an ungoverned action is material. The public anchor chain in this repository is one component of a broader system that includes real-time policy enforcement, decision logging, an operator dashboard, and API access for integration with existing compliance infrastructure.

---

## Technical Specifications

| Property | Value |
|---|---|
| Signature algorithm | Ed25519 |
| Hash function | SHA-256 |
| Proof structure | Binary Merkle tree |
| Anchor format | JSON + detached binary signature |
| Ledger structure | Append-only |
| Anchor delivery | GitHub Releases (tagged) |
| Anchor frequency | Configurable; default per governance batch |
| Chain linkage | Each anchor references previous anchor hash |
| Key management | Per-environment signing keys |
| Verification dependencies | openssl, Python stdlib + merkletools |

All cryptographic primitives used in this repository are standard, widely audited, and available in every major language ecosystem. The verification path has no dependency on any Aegis library, binary, or service.

---

## Live System

The production Aegis system is currently active.

| Metric | Value |
|---|---|
| Governed decisions | 409 (as of 2026-05-13) |
| Environment | Production |
| Mission Control | Operator access only — not publicly accessible |
| Latest anchor | [anchor-test-g46-2026-05-11](https://github.com/isfandkhan123/aegis-anchors/releases/tag/anchor-test-g46-2026-05-11) |

---

## Contact

For questions about this repository, the verification process, or Aegis:

**Email:** isfkhan31@gmail.com  
**Repository:** https://github.com/isfandkhan123/aegis-anchors

For security disclosures related to the anchor chain or signing infrastructure, use the email above with subject line `[SECURITY] aegis-anchors`.

---

*This repository contains no Aegis application code. It is a public evidence layer. The contents are designed to be verified, not trusted.*
