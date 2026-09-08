#!/usr/bin/env python3
"""Standalone verifier for an aegis_decision_proof_v1 bundle.

INDEPENDENCE IS THE POINT. This script imports nothing from aegis and reaches no
network, no production API, no database, no localhost, and needs no private key
and no cooperation from Aegis after the bundle was exported. Everything it needs
is inside the bundle. Its only dependency is `cryptography` for Ed25519 (the one
primitive stdlib lacks); hashing and canonical JSON are stdlib.

It proves, in order and independently, each layer of the chain from a disclosed
governed decision up to the publicly anchored checkpoint root:

    DECISION HASH        recompute event_hash from the disclosed decision fields
    DECISION SIGNATURE   Ed25519 over decision_id|envelope_hash, key by key_id
    MERKLE INCLUSION     event_hash is the leaf; path folds to the root
    CHECKPOINT ROOT      inclusion root == the anchored checkpoint root
    ANCHOR SIGNATURE     Ed25519 over the exact published anchor.json bytes
    REGISTERED KEY       both keys resolve to the published key registry

A layer that cannot be checked is a FAIL, never a skip — a proof that cannot be
verified is not a proof.

A second bundle format, aegis_governed_look_proof_v1, carries SEVERAL linked
records of one governed research look (refusals, grant, consumption) and is
verified by verify_look_bundle below with the same primitives. That format is
deliberately UNANCHORED: it proves the records are signed, linked and mutually
consistent, and states plainly that no public anchor covers them. It does NOT
prove they are the only records for the look. See verify_look_bundle.

Usage:
    python3 verify_decision_proof.py <bundle.json>
Exit code 0 iff every layer the bundle format can carry PASSes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except Exception:  # pragma: no cover
    print("FATAL: this verifier requires the 'cryptography' package", file=sys.stderr)
    sys.exit(2)

PROOF_FORMAT = "aegis_decision_proof_v1"
LOOK_PROOF_FORMAT = "aegis_governed_look_proof_v1"

# Fields the ledger adds to the envelope AFTER envelope_hash is computed
# (ledger_client._enrich_envelope adds these post-hash and post-sign), so they
# are NOT part of the signed envelope_hash preimage and must be excluded when
# recomputing it. Applies to v1 and v2 records alike.
_POST_HASH_FIELDS = {
    "envelope_hash", "signature", "signature_status",
    "provenance", "canonical_envelope", "validation_status",
}

# The exact event_hash preimage field order/set — mirrors the ledger's ONE
# canonical compute_event_hash. seq is coerced to int, as there.
_EVENT_HASH_FIELDS = (
    "org_id", "run_id", "seq", "action_type", "tool_name", "payload",
    "policy_decision", "policy_reason", "status", "prev_hash",
)


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_hex64(v) -> bool:
    if not isinstance(v, str) or len(v) != 64:
        return False
    try:
        bytes.fromhex(v)
        return True
    except ValueError:
        return False


def _ed25519_verify(pub_raw_b64: str, message: bytes, sig_b64: str) -> bool:
    try:
        pub = base64.b64decode(pub_raw_b64, validate=True)
        sig = base64.b64decode(sig_b64, validate=True)
        if len(pub) != 32 or len(sig) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, message)
        return True
    except Exception:
        return False


def _raw_from_registry(entry: dict) -> str | None:
    """A registry entry's raw base64 public key (32 bytes), or None."""
    pk = entry.get("public_key")
    if isinstance(pk, str):
        try:
            if len(base64.b64decode(pk, validate=True)) == 32:
                return pk
        except Exception:
            return None
    return None


def _pem_to_raw_b64(pem: str) -> str | None:
    """Extract the 32-byte Ed25519 key from an SPKI PEM, as raw base64."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        k = load_pem_public_key(pem.encode())
        return base64.b64encode(k.public_bytes_raw()).decode()
    except Exception:
        return None


# The cryptographic layers — integrity of the record and its anchoring. These
# are INDEPENDENT of policy provenance: a record can be cryptographically sound
# while its policy provenance is weak (a legacy unregistered_policy record), and
# the verifier must report those axes separately rather than collapsing them.
CRYPTO_LAYERS = [
    "DECISION HASH", "DECISION SIGNATURE", "MERKLE INCLUSION",
    "CHECKPOINT ROOT", "ANCHOR SIGNATURE", "REGISTERED KEY",
]
# Policy-provenance layers — what governed the decision, and whether that is
# committed. Distinct vocabulary by schema, never conflated:
#   POLICY SET COMMITMENT   (v2)  commits to the COMPLETE effective policy set.
#   LEGACY POLICY COMMITMENT (v1) commits only to a registered ADAPTER hash;
#                                 does NOT imply the global guards were committed.
#   POLICY CONTENT MATCH          only when an external policy definition is
#                                 supplied and recomputes to the committed hash.
POLICY_LAYERS = ["POLICY COMMITMENT", "POLICY CONTENT MATCH"]


class Layers:
    NAMES = CRYPTO_LAYERS + POLICY_LAYERS

    def __init__(self):
        self.result: dict[str, tuple] = {}

    def set(self, name, ok, detail="", label=None, status=None):
        # ok may be True/False/None (None = not applicable / skipped)
        self.result[name] = (ok, detail, label, status)

    def _line(self, name):
        ok, detail, label, status = self.result.get(name, (False, "not evaluated", None, None))
        disp = label or name
        tag = status or ("PASS" if ok else ("SKIPPED" if ok is None else "FAIL"))
        line = f"{disp:<28} {tag}"
        if detail and tag != "PASS":
            line += f" — {detail}"
        return line

    def render(self) -> bool:
        for name in CRYPTO_LAYERS + POLICY_LAYERS:
            print(self._line(name))
        crypto_ok = all(self.result.get(n, (False,))[0] is True for n in CRYPTO_LAYERS)
        # Policy provenance passes iff the commitment layer is a real PASS. Content
        # match, when it ran, must also pass; SKIPPED never counts as a pass.
        pc = self.result.get("POLICY COMMITMENT", (False,))[0]
        cm = self.result.get("POLICY CONTENT MATCH", (None,))[0]
        policy_ok = (pc is True) and (cm is not False)
        strict_ok = crypto_ok and policy_ok
        print()
        print(f"{'CRYPTOGRAPHIC INTEGRITY':<28} {'PASS' if crypto_ok else 'FAIL'}")
        print(f"{'POLICY PROVENANCE':<28} {'PASS' if policy_ok else 'FAIL'}")
        print(f"{'STRICT VERIFICATION':<28} {'PASS' if strict_ok else 'FAIL'}")
        # Machine-readable result. These two assertive fields are registered in
        # tests/test_verification_vocabulary.py with DISTINCT meanings so the
        # guard fails if anyone collapses them.
        self.machine = {
            "policy_commitment_verified":
                self.result.get("POLICY COMMITMENT", (False,))[0] is True,
            "policy_content_match_verified":
                self.result.get("POLICY CONTENT MATCH", (None,))[0],
            "crypto_axis": crypto_ok,
            "policy_axis": policy_ok,
            "strict_axis": strict_ok,
        }
        return strict_ok


def verify(bundle: dict, policy_def=None) -> bool:
    if bundle.get("proof_format") == LOOK_PROOF_FORMAT:
        return verify_look_bundle(bundle)

    L = Layers()

    if bundle.get("proof_format") != PROOF_FORMAT:
        for n in Layers.NAMES:
            L.set(n, False, "wrong proof_format")
        return L.render()

    decision = bundle.get("decision") or {}
    envelope = bundle.get("decision_envelope") or {}
    signature = bundle.get("signature") or {}
    inclusion = bundle.get("inclusion") or {}
    anchor = bundle.get("anchor") or {}
    registry = (bundle.get("verification_keys") or {}).get("keys") or []
    reg_by_id = {e.get("key_id"): e for e in registry if isinstance(e, dict)}

    # ── Layer 1: DECISION HASH ────────────────────────────────────────────────
    try:
        preimage = {k: decision.get(k) for k in _EVENT_HASH_FIELDS}
        if preimage.get("seq") is not None:
            preimage["seq"] = int(preimage["seq"])
        recomputed_eh = _sha256_hex(_canonical(preimage).encode())
        claimed_eh = bundle.get("event_hash")
        ok1 = _is_hex64(claimed_eh) and recomputed_eh == claimed_eh
        L.set("DECISION HASH", ok1,
              "" if ok1 else f"recomputed {recomputed_eh} != {claimed_eh}")
    except Exception as e:
        recomputed_eh = None
        L.set("DECISION HASH", False, f"error: {e}")

    # ── Layer 2: DECISION SIGNATURE ───────────────────────────────────────────
    # Recompute envelope_hash from the disclosed envelope (strip signature and
    # envelope_hash), then Ed25519-verify decision_id|envelope_hash under the
    # key resolved BY key_id FROM THE REGISTRY (never the record's own key).
    try:
        key_id = signature.get("key_id")
        decision_id = signature.get("decision_id")
        claimed_env_hash = signature.get("envelope_hash")
        sig_b64 = signature.get("signature")

        unsigned = {k: v for k, v in envelope.items()
                    if k not in _POST_HASH_FIELDS}
        recomputed_env_hash = _sha256_hex(_canonical(unsigned).encode()) if unsigned else None

        reg_entry = reg_by_id.get(key_id)
        trusted_pub = _raw_from_registry(reg_entry) if reg_entry else None

        env_ok = (_is_hex64(claimed_env_hash)
                  and recomputed_env_hash == claimed_env_hash)
        embedded = signature.get("public_key")
        key_match = (embedded is None) or (embedded == trusted_pub)
        sig_ok = bool(trusted_pub) and env_ok and key_match and _ed25519_verify(
            trusted_pub, f"{decision_id}|{claimed_env_hash}".encode(), sig_b64)

        detail = ""
        if not sig_ok:
            if not trusted_pub:
                detail = f"key_id {key_id!r} not in registry"
            elif not env_ok:
                detail = "envelope_hash does not match disclosed envelope"
            elif not key_match:
                detail = "embedded public_key != registered key"
            else:
                detail = "Ed25519 verify failed"
        L.set("DECISION SIGNATURE", sig_ok, detail)
    except Exception as e:
        L.set("DECISION SIGNATURE", False, f"error: {e}")

    # ── Layer 3: MERKLE INCLUSION ─────────────────────────────────────────────
    # The leaf must BE the decision's event_hash, and the path must fold to the
    # inclusion root by the canonical hex-string pairing.
    try:
        leaf = inclusion.get("event_hash")
        path = inclusion.get("merkle_path") or []
        incl_root = inclusion.get("root_hash")
        leaf_is_decision = (leaf == bundle.get("event_hash")) and _is_hex64(leaf)
        cur = leaf if _is_hex64(leaf) else None
        fold_ok = cur is not None and _is_hex64(incl_root)
        if fold_ok:
            for step in path:
                sib = step.get("sibling"); pos = step.get("position")
                if not _is_hex64(sib) or pos not in ("left", "right"):
                    fold_ok = False; break
                cur = _sha256_hex(((sib + cur) if pos == "left"
                                   else (cur + sib)).encode())
            fold_ok = fold_ok and cur == incl_root
        ok3 = leaf_is_decision and fold_ok
        L.set("MERKLE INCLUSION", ok3,
              "" if ok3 else ("leaf != decision event_hash" if not leaf_is_decision
                              else "path does not fold to root"))
    except Exception as e:
        L.set("MERKLE INCLUSION", False, f"error: {e}")

    # ── Layer 4: CHECKPOINT ROOT ──────────────────────────────────────────────
    # The inclusion root, the checkpoint's stated root, and the anchored root in
    # the published anchor.json must be one and the same value.
    try:
        anchor_bytes = base64.b64decode(anchor.get("anchor_json_b64", ""), validate=True)
        anchor_json = json.loads(anchor_bytes.decode("utf-8"))
        anchored_root = anchor_json.get("checkpoint_root")
        incl_root = inclusion.get("root_hash")
        cp_root = (bundle.get("checkpoint") or {}).get("root_hash")
        ok4 = (_is_hex64(anchored_root) and incl_root == anchored_root
               and cp_root == anchored_root)
        L.set("CHECKPOINT ROOT", ok4,
              "" if ok4 else "inclusion/checkpoint/anchor roots disagree")
    except Exception as e:
        anchor_json = None
        L.set("CHECKPOINT ROOT", False, f"error: {e}")

    # ── Layer 5: ANCHOR SIGNATURE ─────────────────────────────────────────────
    # Ed25519 over the EXACT published anchor.json bytes, under the anchor
    # signing key supplied with the bundle.
    try:
        anchor_bytes = base64.b64decode(anchor.get("anchor_json_b64", ""), validate=True)
        anchor_sig_b64 = anchor.get("anchor_sig_b64")
        anchor_pub_b64 = anchor.get("anchor_public_key_b64")
        if not anchor_pub_b64 and anchor.get("anchor_public_key_pem"):
            anchor_pub_b64 = _pem_to_raw_b64(anchor["anchor_public_key_pem"])
        ok5 = bool(anchor_pub_b64) and _ed25519_verify(
            anchor_pub_b64, anchor_bytes, anchor_sig_b64)
        L.set("ANCHOR SIGNATURE", ok5,
              "" if ok5 else "anchor.sig does not verify over anchor.json")
    except Exception as e:
        anchor_pub_b64 = None
        L.set("ANCHOR SIGNATURE", False, f"error: {e}")

    # ── Layer 6: REGISTERED KEY ───────────────────────────────────────────────
    # Neither key is self-attested: the decision key_id is a registry entry, and
    # the anchor key equals the registry's active_signing key.
    try:
        dec_key_registered = signature.get("key_id") in reg_by_id
        active = [e for e in registry if e.get("status") == "active_signing"]
        anchor_registered = any(
            _raw_from_registry(e) == anchor_pub_b64 for e in registry) and bool(
            anchor_pub_b64)
        anchor_is_active = any(
            _raw_from_registry(e) == anchor_pub_b64 for e in active)
        ok6 = dec_key_registered and anchor_registered and anchor_is_active
        detail = ""
        if not ok6:
            if not dec_key_registered:
                detail = "decision key_id not registered"
            elif not anchor_registered:
                detail = "anchor key not in registry"
            elif not anchor_is_active:
                detail = "anchor key is not the active_signing key"
        L.set("REGISTERED KEY", ok6, detail)
    except Exception as e:
        L.set("REGISTERED KEY", False, f"error: {e}")

    # ── Policy provenance (separate axis) ────────────────────────────────────
    envelope = bundle.get("decision_envelope") or {}
    schema = envelope.get("schema_version")
    committed_hash = None
    try:
        if schema == "decision_envelope_v2":
            commit = (envelope.get("context") or {}).get("policy_commitment") or {}
            psh = commit.get("policy_set_hash")
            ok = _is_hex64(psh)
            committed_hash = psh if ok else None
            # PASS means only: the signed decision commits to policy_set_hash X
            # over the COMPLETE effective set. It does NOT mean the content was
            # inspected — that is POLICY CONTENT MATCH.
            L.set("POLICY COMMITMENT", ok,
                  "" if ok else "v2 policy_set_hash missing/malformed",
                  label="POLICY SET COMMITMENT",
                  status="PASS" if ok else "FAIL")
        else:
            ph = envelope.get("policy_hash")
            if _is_hex64(ph):
                # Legacy: commits ONLY to the registered adapter-policy hash — it
                # does NOT commit the global guards. Deliberately weaker label.
                committed_hash = ph
                L.set("POLICY COMMITMENT", True,
                      label="LEGACY POLICY COMMITMENT", status="PASS")
            else:
                L.set("POLICY COMMITMENT", False,
                      f"legacy {ph!r}" if ph else "no policy hash",
                      label="LEGACY POLICY COMMITMENT", status="FAIL")
    except Exception as e:
        L.set("POLICY COMMITMENT", False, f"error: {e}")

    # POLICY CONTENT MATCH — only when a policy definition is actually supplied.
    # SKIPPED is never silently promoted to PASS.
    try:
        if policy_def is not None and committed_hash:
            recomputed = _sha256_hex(_canonical(policy_def).encode())
            cm = (recomputed == committed_hash)
            L.set("POLICY CONTENT MATCH", cm,
                  "" if cm else "supplied definition does not hash to the commitment",
                  status="PASS" if cm else "FAIL")
        else:
            L.set("POLICY CONTENT MATCH", None,
                  "no external policy definition supplied", status="SKIPPED")
    except Exception as e:
        L.set("POLICY CONTENT MATCH", False, f"error: {e}")

    return L.render()


# ═════════════════════════════════════════════════════════════════════════════
# aegis_governed_look_proof_v1 — several linked records of ONE governed look
# ═════════════════════════════════════════════════════════════════════════════
#
# The bundle carries the refusal records, the grant record and the consumption
# record of a single research look, each in the same disclosed form as a
# decision proof (decision fields, the signed payload, the signature), plus a
# chain declaration, a subject block naming the identities every record must
# agree on, the public key registry, an anchoring block, and a manifest.
#
# WHAT IT PROVES: each record's event_hash recomputes, each signature verifies
# under a REGISTERED key, the declared prev_hash links hold, the records agree
# with each other and with the subject, and the manifest binds all of it.
#
# WHAT IT DOES NOT PROVE: that these are the ONLY records for this look, or
# that the look was not spent elsewhere. That needs the checkpoint the records
# sit in, a Merkle inclusion path, and a public anchor covering it. This
# format carries none of those, and the verifier says so on every run rather
# than skipping the layer silently.

LOOK_RECORD_LAYERS = ["RECORD HASH", "RECORD SIGNATURE", "REGISTERED KEY"]
LOOK_STRUCTURE_LAYERS = ["CHAIN LINKAGE", "LOOK CONSISTENCY", "MANIFEST BINDING"]
LOOK_ABSENT_LAYERS = ["MERKLE INCLUSION", "PUBLIC ANCHOR"]

_LOOK_ROLE_KIND = {
    "refusal": "EXECUTE_FROZEN_EXPERIMENT.refused",
    "grant": "EXECUTE_FROZEN_EXPERIMENT.allow",
    "consumption": "EXECUTE_FROZEN_EXPERIMENT.consumed",
}


def _manifest_hashes(bundle: dict) -> tuple[str, str | None]:
    """(recomputed bundle_content_hash, recomputed manifest_hash or None)."""
    body = {k: v for k, v in bundle.items() if k != "manifest"}
    content_hash = _sha256_hex(_canonical(body).encode())
    manifest = bundle.get("manifest")
    if not isinstance(manifest, dict):
        return content_hash, None
    unsigned = {k: v for k, v in manifest.items() if k != "manifest_hash"}
    return content_hash, _sha256_hex(_canonical(unsigned).encode())


def verify_look_bundle(bundle: dict) -> bool:
    L = Layers()
    L.NAMES = LOOK_RECORD_LAYERS + LOOK_STRUCTURE_LAYERS + LOOK_ABSENT_LAYERS

    records = bundle.get("records") or []
    subject = bundle.get("subject") or {}
    chain = bundle.get("chain") or {}
    registry = (bundle.get("verification_keys") or {}).get("keys") or []
    reg_by_id = {e.get("key_id"): e for e in registry if isinstance(e, dict)}
    anchoring = bundle.get("anchoring") or {}

    def seq_of(rec):
        try:
            return int((rec.get("decision") or {}).get("seq"))
        except Exception:
            return None

    # ── Per-record layers: the same three checks a decision proof runs ──────
    hash_fail, sig_fail, key_fail = [], [], []
    for rec in records:
        s = seq_of(rec)
        decision = rec.get("decision") or {}
        envelope = rec.get("decision_envelope") or {}
        signature = rec.get("signature") or {}
        # RECORD HASH — recompute event_hash from the disclosed fields.
        try:
            preimage = {k: decision.get(k) for k in _EVENT_HASH_FIELDS}
            if preimage.get("seq") is not None:
                preimage["seq"] = int(preimage["seq"])
            eh = _sha256_hex(_canonical(preimage).encode())
            if not (_is_hex64(rec.get("event_hash")) and eh == rec.get("event_hash")):
                hash_fail.append(s)
            # The disclosed envelope must BE the signed payload string, parsed.
            if not isinstance(decision.get("payload"), str) or \
                    json.loads(decision["payload"]) != envelope:
                hash_fail.append(s)
        except Exception:
            hash_fail.append(s)
        # RECORD SIGNATURE — Ed25519 over decision_id|envelope_hash, key from
        # the registry by key_id, never the record's own embedded key.
        try:
            unsigned = {k: v for k, v in envelope.items() if k not in _POST_HASH_FIELDS}
            env_hash = _sha256_hex(_canonical(unsigned).encode()) if unsigned else None
            claimed = signature.get("envelope_hash")
            entry = reg_by_id.get(signature.get("key_id"))
            trusted = _raw_from_registry(entry) if entry else None
            embedded = signature.get("public_key")
            ok = (bool(trusted) and _is_hex64(claimed) and env_hash == claimed
                  and envelope.get("envelope_hash") == claimed
                  and (embedded is None or embedded == trusted)
                  and _ed25519_verify(trusted,
                                      f"{signature.get('decision_id')}|{claimed}".encode(),
                                      signature.get("signature")))
            if not ok:
                sig_fail.append(s)
        except Exception:
            sig_fail.append(s)
        # REGISTERED KEY — the key_id resolves to a registry entry that either
        # signs now or is retained for verification; an unknown key is a FAIL.
        entry = reg_by_id.get(signature.get("key_id"))
        if not (entry and entry.get("status") in ("active_signing", "verify_only")
                and _raw_from_registry(entry)):
            key_fail.append(s)

    n = len(records)
    L.set("RECORD HASH", n > 0 and not hash_fail,
          f"no records" if n == 0 else f"failed for seq {sorted(set(hash_fail))}")
    L.set("RECORD SIGNATURE", n > 0 and not sig_fail,
          f"no records" if n == 0 else f"failed for seq {sorted(set(sig_fail))}")
    L.set("REGISTERED KEY", n > 0 and not key_fail,
          f"no records" if n == 0 else f"unregistered key on seq {sorted(set(key_fail))}")

    # ── CHAIN LINKAGE ────────────────────────────────────────────────────────
    # Every declared link: to.prev_hash == from.event_hash, consecutive seq,
    # same ledger run. Every seq between the first and last record must be
    # either present or DECLARED absent — an undeclared hole is a FAIL, so a
    # record cannot be dropped quietly.
    try:
        by_seq = {seq_of(r): r for r in records}
        seqs = sorted(k for k in by_seq if k is not None)
        run_ids = {(r.get("decision") or {}).get("run_id") for r in records}
        org_ids = {(r.get("decision") or {}).get("org_id") for r in records}
        links = chain.get("links") or []
        declared_absent = {int(g.get("seq")) for g in (chain.get("not_included") or [])}
        link_ok = len(links) > 0 and len(run_ids) == 1 and len(org_ids) == 1
        detail = "" if link_ok else "no links declared or records span several runs"
        for ln in links:
            a, b = by_seq.get(ln.get("from_seq")), by_seq.get(ln.get("to_seq"))
            if not (a and b):
                link_ok, detail = False, f"link {ln} names a record not in the bundle"
                break
            if b["decision"].get("prev_hash") != a.get("event_hash") or \
                    seq_of(b) != seq_of(a) + 1:
                link_ok, detail = False, f"prev_hash of seq {seq_of(b)} != event_hash of seq {seq_of(a)}"
                break
        if link_ok and seqs:
            holes = set(range(seqs[0], seqs[-1] + 1)) - set(seqs)
            if holes != declared_absent:
                link_ok, detail = False, f"undeclared gap in seq: {sorted(holes ^ declared_absent)}"
        if link_ok and len(seqs) != len(records):
            link_ok, detail = False, "duplicate or unnumbered records"
        L.set("CHAIN LINKAGE", link_ok, detail)
    except Exception as e:
        L.set("CHAIN LINKAGE", False, f"error: {e}")

    # ── LOOK CONSISTENCY ─────────────────────────────────────────────────────
    # The records must agree with each other and with the subject block on
    # every identity the page quotes: experiment, registered spec hash,
    # dataset content hash, look key hash, execution id, result hash, and the
    # state path refused → refused → granted → consumed.
    problems = []
    try:
        ordered = sorted(records, key=lambda r: seq_of(r) or 0)
        roles = [r.get("role") for r in ordered]
        if roles != ["refusal", "refusal", "grant", "consumption"]:
            problems.append(f"role sequence {roles}")
        req = subject.get("registered_spec_hash")
        grant = next((r for r in ordered if r.get("role") == "grant"), None)
        cons = next((r for r in ordered if r.get("role") == "consumption"), None)
        g = (grant or {}).get("decision_envelope") or {}
        c = (cons or {}).get("decision_envelope") or {}
        for r in ordered:
            env = r.get("decision_envelope") or {}
            dec = r.get("decision") or {}
            s = seq_of(r)
            if env.get("kind") != _LOOK_ROLE_KIND.get(r.get("role")):
                problems.append(f"seq {s}: kind {env.get('kind')!r} does not match role")
            if env.get("adapter") != "research_looks" or dec.get("action_type") != "RESEARCH_LOOK_TRANSITION":
                problems.append(f"seq {s}: not a research_looks transition")
            if env.get("agent_id") != subject.get("agent_id") or env.get("run_id") != subject.get("run_id"):
                problems.append(f"seq {s}: agent/run differ from subject")
            if env.get("experiment_id") != subject.get("experiment_id"):
                problems.append(f"seq {s}: experiment_id differs from subject")
            if r.get("role") == "refusal":
                rq = env.get("requested") or {}
                if dec.get("policy_decision") != "block" or env.get("policy_verdict") != "BLOCK":
                    problems.append(f"seq {s}: refusal not recorded as BLOCK")
                if "spec_hash_mismatch" not in (env.get("reasons") or []):
                    problems.append(f"seq {s}: refusal reason is not spec_hash_mismatch")
                if not _is_hex64(rq.get("spec_hash")) or rq.get("spec_hash") == req:
                    problems.append(f"seq {s}: presented spec_hash does not differ from the registered one")
                if rq.get("dataset_content_hash") != subject.get("dataset_content_hash") \
                        or rq.get("dataset_id") != subject.get("dataset_id"):
                    problems.append(f"seq {s}: refused request names a different dataset")
                if rq.get("action") != "EXECUTE_ONCE":
                    problems.append(f"seq {s}: refused action is not EXECUTE_ONCE")
            else:
                if dec.get("policy_decision") != "allow" or env.get("policy_verdict") != "APPROVE":
                    problems.append(f"seq {s}: not recorded as APPROVE")
        # grant: the look key it names, and its hash
        try:
            lk = json.loads(g.get("look_key") or "null")
        except Exception:
            lk = None
        if not isinstance(lk, dict):
            problems.append("grant carries no parseable look_key")
        else:
            expect = {"experiment_id": subject.get("experiment_id"),
                      "spec_hash": req,
                      "dataset_id": subject.get("dataset_id"),
                      "dataset_classification": subject.get("dataset_classification"),
                      "dataset_content_hash": subject.get("dataset_content_hash")}
            for k, v in expect.items():
                if lk.get(k) != v:
                    problems.append(f"grant look_key.{k} != subject")
            kh = _sha256_hex(_canonical(lk).encode())
            if kh != g.get("key_hash") or kh != subject.get("look_key_hash"):
                problems.append("grant key_hash != sha256(canonical look_key) or != subject")
        if g.get("execution_id") != subject.get("execution_id") or not g.get("execution_id"):
            problems.append("grant execution_id != subject")
        if g.get("pre_run_state_hash") != subject.get("pre_run_state_hash"):
            problems.append("grant pre_run_state_hash != subject")
        # consumption: bound to the same execution, key and request; carries the result hash
        for k in ("execution_id", "key_hash", "request_id", "pre_run_state_hash"):
            if c.get(k) != g.get(k):
                problems.append(f"consumption {k} != grant {k}")
        if not _is_hex64(c.get("result_hash")) or c.get("result_hash") != subject.get("result_hash"):
            problems.append("consumption result_hash != subject")
        if subject.get("final_state") != "CONSUMED":
            problems.append("subject final_state is not CONSUMED")
        if (c.get("consumed_at") or "") <= (g.get("reserved_at") or "~"):
            problems.append("consumed_at is not after reserved_at")
    except Exception as e:
        problems.append(f"error: {e}")
    L.set("LOOK CONSISTENCY", not problems, "; ".join(problems[:4]))

    # ── MANIFEST BINDING ─────────────────────────────────────────────────────
    # The manifest names every record (id, seq, event_hash), the signers, the
    # look identities, the final state and the anchoring status, commits to
    # the rest of the bundle by hash, and is itself hashed.
    try:
        manifest = bundle.get("manifest") or {}
        content_hash, manifest_hash = _manifest_hashes(bundle)
        m_ok = manifest_hash is not None and manifest.get("manifest_hash") == manifest_hash
        detail = "" if m_ok else "manifest_hash does not recompute"
        if m_ok and manifest.get("bundle_content_hash") != content_hash:
            m_ok, detail = False, "bundle_content_hash does not match bundle body"
        if m_ok and manifest.get("bundle_version") != LOOK_PROOF_FORMAT:
            m_ok, detail = False, "bundle_version mismatch"
        if m_ok:
            named = [(r.get("decision_id"), r.get("seq"), r.get("event_hash"))
                     for r in (manifest.get("records") or [])]
            actual = [(r.get("decision_id"), seq_of(r), r.get("event_hash")) for r in records]
            if named != actual:
                m_ok, detail = False, "manifest records != bundle records"
        if m_ok:
            for k in ("experiment_id", "spec_hash", "dataset_content_hash",
                      "execution_id", "result_hash", "final_state"):
                sk = "registered_spec_hash" if k == "spec_hash" else k
                if manifest.get(k) != subject.get(sk):
                    m_ok, detail = False, f"manifest {k} != subject"
                    break
        if m_ok:
            used = {(r.get("signature") or {}).get("key_id") for r in records}
            named_keys = {s.get("key_id") for s in (manifest.get("signers") or [])}
            if used != named_keys or any(
                    _raw_from_registry(reg_by_id.get(s.get("key_id")) or {}) != s.get("public_key")
                    for s in (manifest.get("signers") or [])):
                m_ok, detail = False, "manifest signers != keys used / registry"
        if m_ok and manifest.get("anchoring_status") != "not_anchored":
            m_ok, detail = False, "manifest anchoring_status must be not_anchored for this format"
        L.set("MANIFEST BINDING", m_ok, detail)
    except Exception as e:
        L.set("MANIFEST BINDING", False, f"error: {e}")

    # ── The two layers this format cannot carry ─────────────────────────────
    # Reported every time, never skipped silently. They are not FAILs of the
    # bundle — the bundle claims nothing here — but they are not PASSes either.
    anchored_claim = anchoring.get("status")
    honest = anchored_claim == "not_anchored" and "inclusion" not in bundle and "anchor" not in bundle
    L.set("MERKLE INCLUSION", None,
          "no checkpoint snapshot contains these records",
          status="NOT ESTABLISHED" if honest else "FAIL")
    L.set("PUBLIC ANCHOR", None,
          f"anchoring halted since {anchoring.get('halted_since', '?')}; "
          f"see {anchoring.get('reference_url', '(no reference)')}",
          status="NOT ESTABLISHED" if honest else "FAIL")

    # ── Render ───────────────────────────────────────────────────────────────
    for name in L.NAMES:
        print(L._line(name))
    rec_ok = all(L.result.get(x, (False,))[0] is True for x in LOOK_RECORD_LAYERS
                 + ["CHAIN LINKAGE", "MANIFEST BINDING"])
    look_ok = L.result.get("LOOK CONSISTENCY", (False,))[0] is True
    overall = rec_ok and look_ok and honest
    print()
    print(f"{'RECORD INTEGRITY':<28} {'PASS' if rec_ok else 'FAIL'}")
    print(f"{'LOOK CONSISTENCY':<28} {'PASS' if look_ok else 'FAIL'}")
    print(f"{'PUBLIC ANCHORING':<28} NOT ESTABLISHED")
    print(f"{'SIGNED-AND-LINKED VERIFICATION':<28} {'PASS' if overall else 'FAIL'}")
    print()
    print("This bundle proves the records above are signed, linked and consistent.")
    print("It does NOT prove they are the only records for this look, or that the")
    print("look was not spent elsewhere: no public anchor covers the checkpoint")
    print("they sit in. That limit is stated by the bundle itself, not discovered.")
    L.machine = {
        "record_integrity_axis": rec_ok,
        "look_consistency_axis": look_ok,
        "anchored": False,
        "signed_and_linked_axis": overall,
    }
    return overall


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    opts = {a.split("=", 1)[0]: (a.split("=", 1)[1] if "=" in a else True)
            for a in argv[1:] if a.startswith("--")}
    if len(args) != 1:
        print("usage: verify_decision_proof.py <bundle.json> [--policy-def=<file>]",
              file=sys.stderr)
        return 2
    with open(args[0], "r", encoding="utf-8") as f:
        bundle = json.load(f)
    policy_def = None
    if opts.get("--policy-def"):
        with open(opts["--policy-def"], "r", encoding="utf-8") as f:
            policy_def = json.load(f)
    return 0 if verify(bundle, policy_def=policy_def) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
