#!/usr/bin/env python3
"""Check checked-in copy/artifact hashes, optionally against an upstream checkout."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
manifest = json.loads((ROOT / "interop/SHA256SUMS.json").read_text())
upstream = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
if upstream:
    revision = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
    assert revision == manifest["upstream_commit"], revision
for item in manifest["entries"]:
    data = (ROOT / item["copy"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == item["sha256"], item["copy"]
    if upstream and "source" in item:
        original = (upstream / item["source"]).read_bytes()
        if "source_lines" in item:
            start, end = item["source_lines"]
            extracted = b"".join(original.splitlines(keepends=True)[start-1:end])
            assert hashlib.sha256(extracted).hexdigest() == item["source_extract_sha256"], item
            assert data.endswith(extracted), item
        else:
            assert data == original, item
print(json.dumps({"valid": True, "entries": len(manifest["entries"]), "upstream_commit": manifest["upstream_commit"]}))
