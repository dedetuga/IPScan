#!/usr/bin/env python3
"""Generate app/oui.txt.gz (MAC vendor table) from the `oui-data` npm package.

    npm pack oui-data && tar xzf oui-data-*.tgz
    python3 tools/gen-oui.py package/index.json app/oui.txt.gz

Output: gzip of "OUIHEX\tVendor\n" lines, sorted. Vendor names are shortened
(company-form suffixes removed) to keep the embedded table small, which matters
on the flash-constrained ARTPEC-4/5 cameras.
"""
import gzip
import json
import re
import sys

SUFFIX = re.compile(
    r"[\s,.]+(co|corp|corporation|inc|incorporated|ltd|limited|llc|l\.l\.c|gmbh|"
    r"ag|ab|a/s|as|sa|s\.a|s\.p\.a|spa|srl|s\.r\.l|bv|b\.v|nv|oy|pte|pty|plc|kg|"
    r"co\.,? ?ltd|technology|technologies|electronics|communications|international)\.?$",
    re.I,
)


def shorten(name: str) -> str:
    name = re.sub(r"\s+", " ", name.split("\n")[0]).strip().strip(",")
    prev = None
    while prev != name:
        prev = name
        name = SUFFIX.sub("", name).strip().strip(",")
    return name or prev


def main(src: str, dst: str) -> None:
    data = json.load(open(src, encoding="utf-8"))
    lines = [f"{k.upper()}\t{shorten(v)}" for k, v in sorted(data.items())]
    blob = ("\n".join(lines) + "\n").encode("utf-8")
    with open(dst, "wb") as f:
        f.write(gzip.compress(blob, 9, mtime=0))
    print(f"{len(lines)} OUIs, {len(blob)} bytes raw -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
