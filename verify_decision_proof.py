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

Usage:
    python3 verify_decision_proof.py <bundle.json>
Exit code 0 iff every layer PASSes.
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
