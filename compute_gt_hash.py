#!/usr/bin/env python3
"""Compute the ground-truth content hash recorded in benchmark-manifest.json.

Algorithm: sha256 over, for each ground-truth/{repo}/ground-truth.json in
sorted path order, the UTF-8 path followed by a newline followed by the raw
file bytes.
"""

import glob
import hashlib


def compute_gt_hash() -> str:
    h = hashlib.sha256()
    for path in sorted(glob.glob("ground-truth/*/ground-truth.json")):
        h.update(path.encode("utf-8"))
        h.update(b"\n")
        h.update(open(path, "rb").read())
    return "sha256:" + h.hexdigest()


if __name__ == "__main__":
    print(compute_gt_hash())
