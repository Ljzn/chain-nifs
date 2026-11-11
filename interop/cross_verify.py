#!/usr/bin/env python3
"""Verify saved or freshly exported native JSON with independent Rust and Go oracles."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent

def run(command, payload, expect=True):
    p = subprocess.run(command, input=json.dumps(payload), text=True, capture_output=True, cwd=ROOT)
    if expect and p.returncode:
        raise AssertionError(f"{command}: {p.stderr} {p.stdout}")
    result = json.loads(p.stdout)
    if expect:
        assert all(c["valid"] for c in result.get("cases", []) + result.get("payments", [])), result
    return p.returncode, result

def main():
    path = Path(sys.argv[1]) if len(sys.argv)>1 else ROOT / "test/fixtures/official_vectors.json"
    payload = json.loads(path.read_text())
    rust = [str(ROOT / "interop/run-rust"), "verify"]
    _, result = run(rust, payload)
    for supplied, official in zip(payload.get("payments", []), result["payments"], strict=True):
        if "receiver" in supplied:
            expected = supplied.get("expected_received")
            assert isinstance(expected, list), "receiver payments require expected_received"
            recovered = official["recovered"]
            assert len(expected) == len(recovered), (expected, recovered)
            for wanted, actual in zip(expected, recovered, strict=True):
                assert all(name in wanted for name in ("index", "amount", "memo_hex")), wanted
                assert all(actual.get(name) == value for name, value in wanted.items()), (wanted, actual)
    if "stealth" in payload:
        run([str(ROOT / "interop/run-go")], payload)
    if payload.get("payments"):
        _, wire = run([str(ROOT / "interop/run-go"), "wire"], payload)
        for official, go in zip(result["payments"], wire["payments"], strict=True):
            for name in ("signing_hash_hex", "txid_hex", "inputs", "outputs", "fee"):
                assert official[name] == go[name], (name, official, go)
        # The signing prefix excludes inputs: changing the external key image must
        # fail its explicit signature binding even with an otherwise valid signature.
        broken = copy.deepcopy(payload["payments"][0])
        raw = bytearray.fromhex(broken["raw_hex"])
        offset = 49
        count = int.from_bytes(raw[37:41], "little")
        for _ in range(count):
            size = int.from_bytes(raw[offset+200:offset+204], "little")
            offset += 204 + size
        raw[offset:offset+32] = raw[1:33]
        broken["raw_hex"] = raw.hex()
        code, rejected = run(rust, {"payments": [broken]}, expect=False)
        assert code != 0 and not rejected["payments"][0]["valid"], rejected
        assert "key image binding mismatch" in rejected["payments"][0]["error"], rejected
    print(json.dumps({"valid": True, "cases": len(result["cases"]), "payments": len(result["payments"]), "oracles": ["official-rust-ABI", "official-go-wallet-extracts", "independent-go-wire"]}))

if __name__ == "__main__":
    main()
