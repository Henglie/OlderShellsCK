#!/usr/bin/env python3
"""Independently check exported instruction bytes and relative calls against original PEs.

Also query raw pointer occurrences or bounded hex windows without loading target code.
SPDX-License-Identifier: Apache-2.0
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct


def rows(path):
    with path.open(encoding="utf-8") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def layout(data):
    nt = struct.unpack_from("<I", data, 60)[0]
    opt = nt + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    base = struct.unpack_from("<I" if magic == 0x10b else "<Q", data, opt + (28 if magic == 0x10b else 24))[0]
    count = struct.unpack_from("<H", data, nt + 6)[0]
    table = opt + struct.unpack_from("<H", data, nt + 20)[0]
    result = [(base, 0, struct.unpack_from("<I", data, opt + 60)[0])]
    for i in range(count):
        rva, size, offset = struct.unpack_from("<III", data, table + 40 * i + 12)
        result.append((base + rva, offset, size))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, type=Path, help="original PE")
    p.add_argument("--output", required=True, type=Path, help="existing per-target evidence directory")
    p.add_argument("--pointer", action="append", default=[], help="find little-endian VA values in original bytes")
    p.add_argument("--dump", action="append", default=[], help="VA:length (integers, e.g. 0x401000:64)")
    a = p.parse_args()
    data = a.input.read_bytes()
    ranges = layout(data)
    def offsets(va, length=1):
        return [raw + va - start for start, raw, size in ranges if 0 <= va - start and va - start + length <= size]
    def vas(raw):
        return [hex(va + raw - start) for va, start, size in ranges if start <= raw < start + size]
    digest = hashlib.sha256(data).hexdigest()
    run = json.loads((a.output / "run.json").read_text(encoding="utf-8"))
    assert digest == run["sha256_before"] == run["sha256_after"], "original hash changed"
    instructions = rows(a.output / "instructions.tsv")
    references = rows(a.output / "references.tsv")
    indexed = {}
    verified, unmapped, calls = 0, 0, 0
    for ins in instructions:
        encoded = bytes.fromhex(ins["bytes"])
        va = int(ins["va"], 16)
        candidates = offsets(va, len(encoded))
        if ins["raw"] == "-":
            assert not candidates, f"unexpected unmapped instruction: {ins}"
            unmapped += 1
            continue
        raw = int(ins["raw"], 16)
        assert candidates == [raw], f"ambiguous/bad VA mapping: {ins}"
        assert data[raw:raw + len(encoded)] == encoded, f"instruction bytes differ: {ins}"
        indexed[ins["va"]] = encoded
        verified += 1
    for ref in references:
        encoded = indexed.get(ref["from_va"], b"")
        if ref["type"] == "UNCONDITIONAL_CALL" and len(encoded) == 5 and encoded[0] == 0xe8:
            target = (int(ref["from_va"], 16) + 5 + struct.unpack_from("<i", encoded, 1)[0]) & 0xffffffff
            assert target == int(ref["to_va"], 16), f"call xref mismatch: {ref}"
            calls += 1
    exported = {}
    for name in ("instructions.tsv", "references.tsv", "functions.tsv", "decompilation.txt", "strings.tsv", "mapping.tsv"):
        exported[name] = hashlib.sha256((a.output / name).read_bytes()).hexdigest()
    decomp = (a.output / "decompilation.txt").read_text(encoding="utf-8")
    result = dict(input_name=a.input.name, sha256=digest, verified_file_backed_instructions=verified,
                  unmapped_instructions=unmapped, verified_direct_calls=calls,
                  functions=len(rows(a.output / "functions.tsv")),
                  decompilation_attempts=decomp.count("\n=== "), decompilation_failures=decomp.count("DECOMPILE_FAILED"),
                  artifact_sha256=exported, passed=True)
    if "source_zip" in run:
        for member in run["source_zip"]["members"]:
            if member.get("extracted"):
                assert hashlib.sha256((a.output / "source" / member["path"]).read_bytes()).hexdigest() == member["sha256"]
        result["source_members_verified"] = len(run["source_zip"]["members"])
    (a.output / "verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "artifact_sha256"}, ensure_ascii=False))
    queries = []
    for pointer in a.pointer:
        pattern = struct.pack("<I", int(pointer, 0))
        start = 0
        while (raw := data.find(pattern, start)) >= 0:
            query = dict(pointer=pointer, raw=hex(raw), va=vas(raw))
            queries.append(query)
            print(json.dumps(query, ensure_ascii=False))
            start = raw + 1
    for window in a.dump:
        value, length = (int(x, 0) for x in window.split(":"))
        if not 0 < length <= 1024:
            raise ValueError("dump length must be 1..1024")
        candidates = offsets(value, length)
        if len(candidates) != 1:
            raise ValueError("dump address has no unique file mapping")
        raw = candidates[0]
        query = dict(va=hex(value), raw=hex(raw), bytes=data[raw:raw + length].hex())
        queries.append(query)
        print(json.dumps(query))
    if queries:
        (a.output / "queries.json").write_text(json.dumps(queries, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
