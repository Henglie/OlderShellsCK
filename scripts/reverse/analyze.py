#!/usr/bin/env python3
"""Read-only PE research via trusted Ghidra headless; outputs stay in --output.

No target executable is launched. Only the selected Java/Ghidra analyzer runs.
SPDX-License-Identifier: Apache-2.0
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import sys
import zipfile


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def pe_layout(data):
    if data[:2] != b"MZ":
        raise ValueError("not MZ")
    nt = struct.unpack_from("<I", data, 0x3c)[0]
    if data[nt:nt + 4] != b"PE\0\0":
        raise ValueError("not PE")
    machine, count = struct.unpack_from("<HH", data, nt + 4)
    opt_size = struct.unpack_from("<H", data, nt + 20)[0]
    opt = nt + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    base = struct.unpack_from("<I" if magic == 0x10b else "<Q", data, opt + (28 if magic == 0x10b else 24))[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    headers = struct.unpack_from("<I", data, opt + 60)[0]
    if count > 96 or headers > len(data):
        raise ValueError("invalid section count/headers")
    ranges = [(base, headers, 0)]
    sections = []
    for n in range(count):
        at = opt + opt_size + n * 40
        name, vs, rva, size, raw = struct.unpack_from("<8sIIII", data, at)
        if raw + size > len(data):
            raise ValueError("section raw range exceeds input")
        ranges.append((base + rva, size, raw))
        sections.append(dict(name=name.rstrip(b"\0").decode("ascii", "replace"),
                             rva=hex(rva), virtual_size=vs, raw=hex(raw), raw_size=size))
    return dict(machine=hex(machine), image_base=hex(base), entry_va=hex(base + entry), sections=sections), ranges


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolroot", type=Path, required=True, help="CTF tool root or Ghidra installation")
    parser.add_argument("--java-home", type=Path, help="Java >=21; otherwise locate toolroot/**/bin/java.exe")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new per-target private evidence directory")
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--source-zip", type=Path, help="list and extract ASM/TXT/RES as inert data")
    parser.add_argument("--function", action="append", default=[], help="additional function entry VA")
    parser.add_argument("--reuse", action="store_true", help="re-export saved project without reanalysis")
    parser.add_argument("--stage-ascii", action="store_true", help="hash-checked private target.exe copy for Ghidra filename restrictions")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()
    source, output, tools = args.input.resolve(), args.output.resolve(), args.toolroot.resolve()
    if not source.is_file():
        parser.error("input must be a file")
    if source == output or output in source.parents or source.parent == output:
        parser.error("output must be separate from original input")
    if output.exists() and not args.reuse:
        parser.error("output already exists; use a new directory or --reuse")
    ghidra = tools if (tools / "Ghidra/application.properties").is_file() else next(iter(sorted(tools.glob("Disassemblers/ghidra_*/Ghidra/application.properties"))), None)
    if ghidra is None:
        parser.error("Ghidra not found")
    if ghidra.is_file():
        ghidra = ghidra.parent.parent
    java = args.java_home / "bin/java.exe" if args.java_home else next(iter(sorted(tools.glob("**/bin/java.exe"))), None)
    if java is None or not java.is_file():
        parser.error("Java not found; supply --java-home")
    java = java.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name in ("home", "temp", "cache", "settings", "projects", "decompiled"):
        (output / name).mkdir(exist_ok=True)
    before = sha(source)
    if args.reuse:
        previous = json.loads((output / "run.json").read_text(encoding="utf-8"))
        if previous["sha256_before"] != before or previous["input_name"] != source.name:
            raise ValueError("saved project belongs to different input bytes/name")
    analyzer_input = source
    if args.stage_ascii:
        analyzer_input = output / "target.exe"
        if not args.reuse:
            analyzer_input.write_bytes(source.read_bytes())
        if sha(analyzer_input) != before:
            raise ValueError("staged input hash mismatch")
    meta, ranges = pe_layout(source.read_bytes())
    meta.update(input_name=source.name, input_size=source.stat().st_size, sha256_before=before,
                target_executed=False, python=sys.version.split()[0])
    meta["staged_ascii_copy"] = args.stage_ascii
    (output / "mapping.tsv").write_text("va\tsize\traw\n" + "".join(f"{hex(v)}\t{hex(s)}\t{hex(r)}\n" for v, s, r in ranges), encoding="utf-8")
    with (output / "strings.tsv").open("w", encoding="utf-8") as stream:
        stream.write("raw\tva\ttext\n")
        for m in re.finditer(rb"[\x20-\x7e]{5,}", source.read_bytes()):
            vas = [hex(v + m.start() - r) for v, s, r in ranges if r <= m.start() < r + s]
            stream.write(f"{hex(m.start())}\t{','.join(vas) or '-'}\t{m[0].decode('ascii')}\n")
    if args.inventory:
        def records(obj):
            if isinstance(obj, dict):
                if obj.get("sha256") == before and obj.get("path"):
                    yield {k: obj[k] for k in ("path", "sha256", "size") if k in obj}
                for value in obj.values():
                    yield from records(value)
            elif isinstance(obj, list):
                for value in obj:
                    yield from records(value)
        meta["inventory_matches"] = list(records(json.loads(args.inventory.read_text(encoding="utf-8"))))
        if not meta["inventory_matches"]:
            raise ValueError("input hash not present in inventory")
    if args.source_zip:
        archive = args.source_zip.resolve()
        zip_before = sha(archive)
        members = []
        dest = output / "source"
        dest.mkdir(exist_ok=True)
        with zipfile.ZipFile(archive) as z:
            if sum(i.file_size for i in z.infolist()) > 4 * 1024 * 1024:
                raise ValueError("source archive exceeds 4 MiB budget")
            for i in z.infolist():
                p = PurePosixPath(i.filename.replace("\\", "/"))
                if p.is_absolute() or ".." in p.parts or ":" in i.filename or (i.external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("unsafe archive path")
                record = dict(path=i.filename, size=i.file_size, crc32=f"{i.CRC:08x}")
                if not i.is_dir() and p.suffix.lower() in (".asm", ".txt", ".res"):
                    data = z.read(i)
                    target = dest.joinpath(*p.parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
                    record.update(extracted=True, sha256=hashlib.sha256(data).hexdigest())
                members.append(record)
        zip_after = sha(archive)
        meta["source_zip"] = dict(name=archive.name, sha256_before=zip_before,
                                  sha256_after=zip_after, unchanged=zip_before == zip_after, members=members)
        if zip_before != zip_after:
            raise ValueError("source archive changed")
    properties = (ghidra / "Ghidra/application.properties").read_text(encoding="utf-8")
    meta["ghidra_version"] = re.search(r"^application.version=(.*)$", properties, re.M)[1].strip()
    meta["java_version"] = subprocess.run([str(java), "-version"], capture_output=True, text=True, check=True).stderr.strip()
    scripts = Path(__file__).resolve().parent
    meta["automation_sha256"] = {name: sha(scripts / name) for name in ("analyze.py", "StaticEvidence.java")}
    command = [str(java), "-Xmx2G", "-Xshare:off", "--enable-native-access=ALL-UNNAMED",
               "-Djava.system.class.loader=ghidra.GhidraClassLoader", "-Dfile.encoding=UTF-8",
               "-Djava.awt.headless=true", "-Duser.language=en", "-Duser.country=US",
               "-Djavax.xml.accessExternalDTD=", "-Djavax.xml.accessExternalSchema=", "-Djavax.xml.accessExternalStylesheet="]
    for prop, directory in (("user.home", "home"), ("java.io.tmpdir", "temp"),
                            ("application.cachedir", "cache"), ("application.settingsdir", "settings")):
        command.append(f"-D{prop}={output / directory}")
    command += ["-cp", str(ghidra / "Ghidra/Framework/Utility/lib/Utility.jar"), "ghidra.Ghidra",
                "ghidra.app.util.headless.AnalyzeHeadless", str(output / "projects"), "research"]
    command += ["-process", analyzer_input.name, "-noanalysis"] if args.reuse else ["-import", str(analyzer_input)]
    command += ["-analysisTimeoutPerFile", str(args.timeout), "-max-cpu", "2", "-scriptPath", str(scripts),
                "-postScript", "StaticEvidence.java", str(output), *args.function,
                "-log", str(output / "ghidra.log"), "-scriptlog", str(output / "script.log")]
    replacements = [(str(output), "<OUTPUT>"), (str(source), "<INPUT>"), (str(java.parent.parent), "<JAVA_HOME>"),
                    (str(ghidra), "<GHIDRA>"), (str(scripts), "<SCRIPTS_REVERSE>")]
    def redact(part):
        for old, new in sorted(replacements, key=lambda item: -len(item[0])):
            part = part.replace(old, new)
        return part
    meta["command_argv"] = [redact(part) for part in command]
    env = os.environ.copy()
    env.update(TEMP=str(output / "temp"), TMP=str(output / "temp"), USERPROFILE=str(output / "home"),
               APPDATA=str(output / "home"), LOCALAPPDATA=str(output / "cache"))
    (output / "export-complete.txt").unlink(missing_ok=True)
    try:
        with (output / "console.log").open("w", encoding="utf-8") as stream:
            result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                    env=env, cwd=output, timeout=args.timeout + 900)
        meta["analyzer_exit_code"] = result.returncode
        meta["export_complete"] = (output / "export-complete.txt").is_file()
        console = (output / "console.log").read_text(encoding="utf-8", errors="replace")
        meta["analysis_timeout_reported"] = bool(re.search(r"analysis.*timed out|analysis.*timeout occurred", console, re.I))
    finally:
        meta["sha256_after"] = sha(source)
        meta["input_unchanged"] = before == meta["sha256_after"]
        if args.stage_ascii:
            meta["staged_sha256_after"] = sha(analyzer_input)
            meta["input_unchanged"] &= before == meta["staged_sha256_after"]
        write_json(output / ("run-reuse.json" if args.reuse else "run.json"), meta)
    print(json.dumps({k: meta.get(k) for k in ("input_name", "sha256_before", "input_unchanged", "ghidra_version", "analyzer_exit_code", "export_complete")}, ensure_ascii=False))
    if not meta["input_unchanged"] or not meta.get("export_complete") or meta.get("analyzer_exit_code") or meta.get("analysis_timeout_reported"):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
