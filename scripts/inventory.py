#!/usr/bin/env python3
"""Static, deterministic archive inventory. Python 3.10+, standard library only.

Only the explicitly supplied, external 7-Zip executable is invoked, for listing.
No extracted executable, DLL, script, or nested archive payload is executed.
Paths in the JSON are relative to --root. --verify recomputes without writing.
"""

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import stat
import struct
import subprocess
import sys
import zipfile
import zlib


API_GROUPS = {
    "debugging": {
        "DebugActiveProcess", "DebugActiveProcessStop", "WaitForDebugEvent",
        "WaitForDebugEventEx", "ContinueDebugEvent", "DebugSetProcessKillOnExit",
        "GetThreadContext", "SetThreadContext", "Wow64GetThreadContext",
        "Wow64SetThreadContext", "NtDebugActiveProcess", "NtWaitForDebugEvent",
    },
    "remote_memory": {
        "ReadProcessMemory", "WriteProcessMemory", "VirtualAllocEx",
        "VirtualProtectEx", "VirtualQueryEx", "CreateRemoteThread",
        "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx",
    },
    "process_control": {
        "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA",
        "CreateProcessAsUserW", "OpenProcess", "OpenThread", "SuspendThread",
        "ResumeThread", "TerminateProcess", "CreateToolhelp32Snapshot",
        "Process32First", "Process32FirstW", "Process32Next", "Process32NextW",
        "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
        "WinExec", "NtCreateUserProcess",
    },
    "file_io": {
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "SetFilePointer",
        "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile",
        "UnmapViewOfFile", "fopen", "fread", "fwrite", "_open", "_read", "_write",
    },
    "decompression": {
        "RtlDecompressBuffer", "RtlDecompressBufferEx", "inflate", "inflateInit_",
        "inflateInit2_", "uncompress", "BZ2_bzDecompress", "lzma_code",
    },
    "dynamic_resolution": {"LoadLibraryA", "LoadLibraryW", "GetProcAddress", "LdrGetProcedureAddress"},
    "anti_debug_checks": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"},
}
ALL_APIS = set().union(*API_GROUPS.values())
TEXT_EXT = {".txt", ".nfo", ".diz", ".md", ".htm", ".html", ".ini", ".cfg", ".log", ".config", ".manifest", ".url"}
SOURCE_EXT = {".c", ".cc", ".cpp", ".h", ".hpp", ".asm", ".inc", ".pas", ".dpr", ".py", ".js", ".au3", ".rs", ".go", ".cs", ".vb", ".bas", ".vbs", ".bat", ".cmd", ".ps1", ".sh"}
ARCHIVE_EXT = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".cab", ".arj", ".lzh", ".tgz"}
LICENSE_RE = re.compile(r"licen[cs]e|copyright|\b(?:GPL|LGPL|MIT|BSD)\b|GNU |freeware|public domain|redistribut|all rights reserved|source code|open.source|许可|版权|开源|源码", re.I)
IDENTITY_RE = re.compile(r"version|unpack|decompress|static|debug|nanomite|protector|pack(?:er|ing)|armadillo|aspack|asprotect|upx|fsg|mew|nspack|petite|molebox|autoit|execryptor|themida|obsidium|pecompact|copyright|license|\bv\d+\.\d+", re.I)
VERSION_KEYS = {"CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "LegalTrademarks", "OriginalFilename", "ProductName", "ProductVersion", "Comments", "PrivateBuild", "SpecialBuild"}

# Explicitly named plugin targets; generic plugins / compiler names are excluded.
PLUGIN_FAMILIES = {
    "acprotect": "ACProtect", "armadillo": "Armadillo", "armprotector": "ArmProtector",
    "aspack": "ASPack", "asprotect": "ASProtect", "beroexepacker": "BeRoExePacker",
    "dbpe": "DBPE", "execryptor": "EXECryptor", "expressor": "eXPressor", "fsg": "FSG",
    "getepeinfo": "EncryptPE", "hmimys": "Hmimys", "hying": "Hying", "hying04x": "Hying",
    "jdpack": "JDPack", "kbys": "KByS", "kenpack": "KenPack", "mew": "MEW",
    "morphine": "Morphine", "nspack": "NsPack", "orien": "ORiEN", "packman": "PackMan",
    "pcshrink": "PC Shrinker", "pecompact": "PECompact", "pelock": "PELock",
    "pencrypt": "PEncrypt", "pespin": "PESpin", "petite": "Petite", "polyene": "PolyEnE",
    "rlpack": "RLPack", "shoooo": "Shoooo", "starforce": "StarForce", "telock": "tElock",
    "upack": "Upack/WinUpack", "upx": "UPX", "vcasm": "VCasm", "yoda": "yoda's Protector",
}
PATH_FAMILIES = {
    "Armadillo": r"armageddon|arminline|armadillo|穿山甲",
    "DDeM Protector": r"ddem", "EncryptPE": r"encryptpe|epe[_ 0-9]",
    "MoleBox": r"molebox", "Obsidium": r"obsidium", "PEArmor": r"pearmor",
    "EXECryptor": r"execryptor", "PECompact": r"pecompact", "PESpin": r"pespin",
    "Petite": r"unpetite", "SafeDisc": r"safedisc", "tElock": r"telock",
    "Upack/WinUpack": r"winupack", "FSG": r"unfsg|defsg", "ASPack": r"deaspack|aspackdie",
    "MEW": r"demew", "NsPack": r"denspack|北斗",
    "PackMan": r"depackman", "PeX": r"depex", "UPX": r"deupx|(?:^|/)upx\.exe$|upxunpacker",
    "ORiEN": r"^orien\.exe$", "yoda's Protector": r"yoda",
}
AORE_FAMILIES = [
    "!EP (EXE Pack)", "antiOllyDBG", "ASDPack", "ASPack", "AverCryptor", "CryptX",
    "dePack", "DexCrypt", "eXPressor", "GHF Protector", "HidePE", "HidePX",
    "JeyJey UPX Protector", "MEW", "MoleBox", "Morphnah", "NsPack", "PackMan",
    "PC Shrinker", "PE Lock NT", "PE Pack", "PECompact", "Pohernah", "PolyEnE",
    "RCryptor", "ReCrypt", "SimplePack", "Ste@lth PE", "The Best Cryptor",
    "Mucki's Protector", "UPX", "UPXScramb",
]


def digest(path):
    with path.open("rb") as stream:
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe_member(name):
    name = name.replace("\\", "/")
    parts = name.split("/")
    if (not name or PureWindowsPath(name).drive or name.startswith("/")
            or any(p in {"", ".", ".."} or p.endswith((" ", ".")) for p in parts)
            or re.search(r'[\x00-\x1f:<>"|?*]', name)
            or any(re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", p) for p in parts)):
        raise ValueError(f"Unsafe archive member: {name!r}")
    return name


def list_archive(sevenzip, archive):
    result = subprocess.run(
        [str(sevenzip), "l", "-slt", "-sccUTF-8", "--", str(archive)],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=120,
    )
    if result.returncode:
        raise ValueError(f"7-Zip listing failed ({result.returncode}); password or damaged archive unresolved")
    text = result.stdout.decode("utf-8-sig", "strict").replace("\r\n", "\n")
    if "----------\n" not in text:
        raise ValueError("7-Zip entry separator missing")
    header, body = text.split("----------\n", 1)
    entries = []
    seen = set()
    for record in body.strip().split("\n\n"):
        fields = dict(line.split(" = ", 1) for line in record.splitlines() if " = " in line)
        if "Path" not in fields:
            continue
        name = safe_member(fields["Path"])
        if name.casefold() in seen:
            raise ValueError(f"Case-insensitive duplicate archive path: {name}")
        seen.add(name.casefold())
        if fields.get("Symbolic Link") or fields.get("Hard Link") or "Reparse" in fields.get("Attributes", ""):
            raise ValueError(f"Link archive member: {name}")
        entries.append({
            "path": name, "is_directory": fields.get("Folder") == "+" or "D" in fields.get("Attributes", ""),
            "size": int(fields.get("Size") or 0), "crc32": fields.get("CRC") or None,
            "encrypted": fields.get("Encrypted") == "+", "modified": fields.get("Modified"),
        })
    if not entries:
        raise ValueError("Empty or unparseable archive listing")
    version = next((line for line in header.splitlines() if line.startswith("7-Zip ")), "unknown")
    return version, sorted(entries, key=lambda e: e["path"])


class PE:
    """Bounds-checked on-disk PE parser; never loads a module into the OS."""

    def __init__(self, data):
        self.data = data
        self.sections = []
        self.directories = []
        self.warnings = []

    def unpack(self, fmt, offset):
        length = struct.calcsize("<" + fmt)
        if offset < 0 or offset + length > len(self.data):
            raise ValueError(f"Truncated structure at offset {offset}")
        return struct.unpack_from("<" + fmt, self.data, offset)

    def rva(self, address, length=1):
        if address < self.headers and address + length <= min(self.headers, len(self.data)):
            return address
        for section in self.sections:
            delta = address - section["rva"]
            if 0 <= delta and delta + length <= section["raw_size"]:
                offset = section["raw_offset"] + delta
                if offset + length <= len(self.data):
                    return offset
        raise ValueError(f"Unmapped RVA 0x{address:x} (length {length})")

    def cstring(self, address):
        offset = self.rva(address)
        end = self.data.find(b"\0", offset, min(len(self.data), offset + 4096))
        if end == -1:
            raise ValueError(f"Unterminated string at RVA 0x{address:x}")
        self.rva(address, end - offset + 1)
        return self.data[offset:end].decode("ascii", "replace")

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def thunks(self, address, values_are_va=False):
        names = []
        width = 8 if self.is64 else 4
        ordinal_mask = 1 << (width * 8 - 1)
        for index in range(65536):
            value, = self.unpack("Q" if self.is64 else "I", self.rva(address + index * width, width))
            if not value:
                return names
            names.append(f"#{value & 0xffff}" if value & ordinal_mask else self.cstring(value - (self.image_base if values_are_va else 0) + 2))
        raise ValueError("Import thunk limit exceeded")

    def imports(self, delay=False):
        address, size = self.directory(13 if delay else 1)
        if not address or not size:
            return []
        records = []
        stride = 32 if delay else 20
        for index in range(min(size // stride, 4096)):
            try:
                fields = self.unpack("8I" if delay else "5I", self.rva(address + stride * index, stride))
                if not any(fields):
                    return records
                if delay:
                    flags, name, _, iat, names, _, _, _ = fields
                    if not flags & 1:
                        name -= self.image_base
                        names = (names or iat) - self.image_base
                else:
                    names, _, _, name, iat = fields
                dll = self.cstring(name)
                record = {"dll": dll, "symbols": []}
                records.append(record)
                record["symbols"] = self.thunks(names or iat, values_are_va=delay and not flags & 1)
            except ValueError as error:
                self.warnings.append(f"{'delay ' if delay else ''}imports: {error}")
                return records
        self.warnings.append("Import directory lacks terminator within declared size / limit")
        return records

    def exports(self):
        address, size = self.directory(0)
        if not address or not size:
            return {}
        fields = self.unpack("IIHHIIIIIII", self.rva(address, 40))
        _, _, _, _, name, base, count, named_count, functions, names, ordinals = fields
        if max(count, named_count) > 200000:
            raise ValueError("Export count limit exceeded")
        by_index = defaultdict(list)
        for i in range(named_count):
            name_rva, = self.unpack("I", self.rva(names + 4 * i, 4))
            index, = self.unpack("H", self.rva(ordinals + 2 * i, 2))
            if index >= count:
                raise ValueError("Export ordinal outside function table")
            by_index[index].append(self.cstring(name_rva))
        symbols = []
        for i in range(count):
            function, = self.unpack("I", self.rva(functions + 4 * i, 4))
            if function:
                symbols.append({"ordinal": base + i, "names": by_index[i], "rva": function,
                                "forwarder": self.cstring(function) if address <= function < address + size else None})
        return {"dll_name": self.cstring(name) if name else None, "symbols": symbols}

    def version_info(self):
        address, size = self.directory(2)
        if not address or not size:
            return []
        blobs = []
        visited = set()

        def resource_offset(relative, length):
            if relative < 0 or relative + length > size:
                raise ValueError("Resource structure outside directory")
            return self.rva(address + relative, length)

        def walk(relative, depth, is_version):
            if relative in visited or depth > 4:
                raise ValueError("Cyclic/deep resource directory")
            visited.add(relative)
            fields = self.unpack("IIHHHH", resource_offset(relative, 16))
            count = fields[-1] + fields[-2]
            if count > 8192:
                raise ValueError("Resource entry limit exceeded")
            for i in range(count):
                key, target = self.unpack("II", resource_offset(relative + 16 + 8 * i, 8))
                selected = is_version or (depth == 0 and key == 16)
                if not selected:
                    continue
                if target & 0x80000000:
                    walk(target & 0x7fffffff, depth + 1, selected)
                else:
                    rva, length, codepage, _ = self.unpack("4I", resource_offset(target, 16))
                    offset = self.rva(rva, length)
                    blobs.append((self.data[offset:offset + length], codepage))

        walk(0, 0, False)
        versions = []
        for blob, codepage in blobs:
            result = {"codepage": codepage, "strings": {}}

            def node(start, limit, depth=0):
                if depth > 8 or start + 6 > limit:
                    raise ValueError("Malformed version node")
                length, value_length, kind = struct.unpack_from("<HHH", blob, start)
                end = start + length
                if length < 6 or end > limit:
                    raise ValueError("Invalid version node length")
                pos = start + 6
                key_end = pos
                while key_end + 2 <= end and blob[key_end:key_end + 2] != b"\0\0":
                    key_end += 2
                if key_end + 2 > end:
                    raise ValueError("Unterminated version key")
                key = blob[pos:key_end].decode("utf-16le", "replace")
                pos = (key_end + 2 + 3) & ~3
                value_bytes = value_length * (2 if kind == 1 else 1)
                if value_bytes and pos + value_bytes > end:
                    raise ValueError("Version value exceeds node")
                value = blob[pos:pos + value_bytes]
                if key == "VS_VERSION_INFO" and len(value) >= 52:
                    fixed = struct.unpack_from("<13I", value)
                    if fixed[0] == 0xfeef04bd:
                        for label, hi, lo in (("file_version", fixed[2], fixed[3]), ("product_version", fixed[4], fixed[5])):
                            result[label] = ".".join(map(str, (hi >> 16, hi & 65535, lo >> 16, lo & 65535)))
                elif key in VERSION_KEYS and kind == 1:
                    result["strings"].setdefault(key, []).append(value.decode("utf-16le", "replace").rstrip("\0"))
                pos = (pos + value_bytes + 3) & ~3
                while pos + 6 <= end:
                    if blob[pos:pos + 2] == b"\0\0":
                        break
                    pos = (node(pos, end, depth + 1) + 3) & ~3
                return end

            node(0, len(blob))
            versions.append(result)
        return versions

    def parse(self):
        if self.data[:2] != b"MZ":
            return None
        offset, = self.unpack("I", 0x3c)
        if offset + 24 > len(self.data) or self.data[offset:offset + 4] != b"PE\0\0":
            return {"format": "MZ/non-PE", "warnings": ["No valid PE signature"]}
        machine, count, timestamp, _, _, opt_size, flags = self.unpack("HHIIIHH", offset + 4)
        optional = offset + 24
        self.unpack(f"{opt_size}s", optional)
        magic, = self.unpack("H", optional)
        if magic not in {0x10b, 0x20b}:
            raise ValueError(f"Unsupported optional header 0x{magic:x}")
        self.is64 = magic == 0x20b
        minimum = 112 if self.is64 else 96
        if opt_size < minimum or count > 1024:
            raise ValueError("Invalid optional header / section count")
        self.image_base, = self.unpack("Q" if self.is64 else "I", optional + (24 if self.is64 else 28))
        self.headers, = self.unpack("I", optional + 60)
        entrypoint, = self.unpack("I", optional + 16)
        subsystem, = self.unpack("H", optional + 68)
        directory_count, = self.unpack("I", optional + minimum - 4)
        for i in range(min(directory_count, (opt_size - minimum) // 8, 16)):
            self.directories.append(self.unpack("II", optional + minimum + 8 * i))
        for i in range(count):
            name, virtual_size, rva, raw_size, raw_offset, _, _, _, _, characteristics = self.unpack("8sIIIIIIHHI", optional + opt_size + 40 * i)
            self.sections.append({"name": name.rstrip(b"\0").decode("ascii", "replace"), "rva": rva,
                                  "virtual_size": virtual_size, "raw_size": raw_size,
                                  "raw_offset": raw_offset, "characteristics": characteristics})
            if raw_size and raw_offset + raw_size > len(self.data):
                self.warnings.append(f"Section {i} raw data exceeds file")
        result = {"format": "PE32+" if self.is64 else "PE32", "machine": f"0x{machine:04x}",
                  "architecture": {0x14c: "x86", 0x8664: "x64", 0x1c0: "ARM", 0x1c4: "ARMv7", 0xaa64: "ARM64"}.get(machine, "unknown"),
                  "coff_timestamp": timestamp, "is_dll": bool(flags & 0x2000),
                  "subsystem": subsystem, "entrypoint_rva": entrypoint,
                  "managed_clr_directory": bool(self.directory(14)[0]), "sections": self.sections,
                  "imports": self.imports(), "delay_imports": self.imports(True)}
        for key, fn in (("exports", self.exports), ("version_resources", self.version_info)):
            try:
                result[key] = fn()
            except (ValueError, struct.error) as error:
                result[key] = {} if key == "exports" else []
                self.warnings.append(f"{key}: {error}")
        result["warnings"] = self.warnings
        return result


def printable_strings(data):
    for encoding, pattern in (("ascii", rb"[\x20-\x7e]{5,}"), ("utf-16le", rb"(?:[\x20-\x7e]\x00){5,}")):
        for match in re.finditer(pattern, data):
            yield match.start(), encoding, match.group().decode(encoding)


def string_evidence(data):
    api_strings = set()
    identity = []
    total = 0
    seen = set()
    license_strings = []
    license_seen = set()
    api_pattern = re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(sorted(ALL_APIS)) + r")(?![A-Za-z0-9_])")
    for offset, encoding, text in printable_strings(data):
        api_strings.update(api_pattern.findall(text))
        if len(text) <= 512 and LICENSE_RE.search(text) and text not in license_seen and not re.search(r"[A-Za-z]:[\\/]|\\\\", text):
            license_seen.add(text)
            if len(license_strings) < 80:
                license_strings.append({"offset": offset, "encoding": encoding, "value": text})
        if len(text) <= 512 and IDENTITY_RE.search(text) and text not in seen:
            # Do not copy build-machine absolute paths into the inventory.
            if re.search(r"[A-Za-z]:[\\/]|\\\\", text):
                continue
            seen.add(text)
            total += 1
            if len(identity) < 100:
                identity.append({"offset": offset, "encoding": encoding, "value": text})
    return {"api_names": sorted(api_strings), "identity_version_license": identity,
            "license_mentions": license_strings, "license_mention_count": len(license_seen), "license_limit": 80,
            "identity_matches": total, "identity_retained": len(identity), "identity_limit": 100}


def decode_text(data):
    encodings = (["utf-16"] if data.startswith((b"\xff\xfe", b"\xfe\xff")) else []) + ["utf-8-sig", "gb18030", "cp1252"]
    for encoding in encodings:
        try:
            return data.decode(encoding), encoding
        except UnicodeError:
            pass
    return data.decode("latin1"), "latin1"


def text_evidence(data):
    text, encoding = decode_text(data)
    lines = text.splitlines()
    def matches(pattern):
        return [{"line": i, "text": line[:1000]} for i, line in enumerate(lines, 1) if pattern.search(line)]
    license_hits = matches(LICENSE_RE)
    identity_hits = matches(IDENTITY_RE)
    return {"encoding_guess": encoding, "line_count": len(lines), "license_mentions": license_hits[:80],
            "license_mention_count": len(license_hits), "identity_mentions": identity_hits[:80],
            "identity_mention_count": len(identity_hits), "excerpt_limit": 80}


def nested_inventory(path, sevenzip):
    """Metadata listing only; ZIP payloads are never opened/decompressed."""
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                entries = [{"path": item.filename, "is_directory": item.is_dir(),
                            "size": item.file_size, "compressed_size": item.compress_size,
                            "crc32": f"{item.CRC:08X}", "encrypted": bool(item.flag_bits & 1),
                            "is_symlink": stat.S_ISLNK(item.external_attr >> 16)} for item in archive.infolist()]
            method = "zipfile.infolist (metadata only)"
        else:
            _, entries = list_archive(sevenzip, path)
            method = "external 7-Zip l (metadata only)"
        unsafe = []
        for entry in entries:
            try:
                safe_member(entry["path"].rstrip("/\\"))
            except ValueError:
                unsafe.append(entry["path"])
        return {"status": "listed_not_extracted", "method": method, "entries": entries,
                "unsafe_paths": unsafe, "source_members": [e["path"] for e in entries if Path(e["path"]).suffix.lower() in SOURCE_EXT],
                "license_named_members": [e["path"] for e in entries if re.search(r"(?i)(license|licence|copying|copyright)", e["path"])],
                "encrypted_members": [e["path"] for e in entries if e["encrypted"]]}
    except (ValueError, OSError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        return {"status": "unresolved", "error": type(error).__name__ + ": metadata listing failed; password/damage not distinguished"}


def api_evidence(pe, strings):
    imported = {symbol for record in (pe or {}).get("imports", []) + (pe or {}).get("delay_imports", []) for symbol in record["symbols"]}
    groups = {name: {"imports": sorted(apis & imported), "strings_only": sorted((apis & set(strings["api_names"])) - imported)} for name, apis in API_GROUPS.items()}
    if any(groups[g]["imports"] for g in ("debugging", "remote_memory")):
        assessment = "debug_or_remote_memory_imports"
    elif any(groups[g]["strings_only"] for g in ("debugging", "remote_memory")):
        assessment = "debug_or_remote_memory_strings_only"
    elif groups["process_control"]["imports"]:
        assessment = "process_control_imports_only"
    elif groups["file_io"]["imports"] or groups["decompression"]["imports"]:
        assessment = "file_or_decompression_imports_only_candidate"
    else:
        assessment = "insufficient_visible_evidence"
    return {"groups": groups, "assessment": assessment,
            "caveat": "Imports/strings are clues, not executed behavior; absence cannot prove static-only operation."}


def family_evidence(files, root):
    evidence = defaultdict(list)
    for file in files:
        path = file["path"]
        pure = Path(path)
        if "/CoolDumpper/plugin/" in path and pure.stem.lower() in PLUGIN_FAMILIES:
            evidence[PLUGIN_FAMILIES[pure.stem.lower()]].append({"path": path, "basis": "plugin_filename"})
        for family, pattern in PATH_FAMILIES.items():
            # Exclude samples and text/data: the containing tool directory is supporting evidence.
            if pure.suffix.lower() in {".exe", ".dll"} and re.search(pattern, "/".join(pure.parts[1:]), re.I):
                evidence[family].append({"path": path, "basis": "tool_path"})
        if pure.name == "tested.packers.txt" and "AoRE_Unpacker" in path:
            lines = (root / path).read_text(encoding="ascii").splitlines()
            # Positional normalization is allowed only for this exact historical list.
            prefixes = ["!EP_", "antiOllyDBG", "ASDPack", "ASPack", "AverCryptor", "CryptX", "dePack", "DexCrypt", "eXPressor", "GHF Protector", "HidePE", "HidePX", "JeyJey_", "MEW_", "Molebox", "Morphnah", "NsPack", "Packman", "PC Shrinker", "PE_Lock_NT", "PE Pack", "PeCompact", "Pohernah", "PolyEnE", "RCryptor", "ReCrypt", "SimplePack", "Ste@lth", "The Best Cryptor", "Mucki's", "UPX ", "UPXScramb"]
            if len(lines) == len(prefixes) and all(line.startswith(prefix) for line, prefix in zip(lines, prefixes)):
                for i, (family, line) in enumerate(zip(AORE_FAMILIES, lines), 1):
                    evidence[family].append({"path": path, "basis": "bundled_author_claim_not_verified", "line": i, "claim": line.strip()})
    return [{"name": name, "evidence": evidence[name], "verified_supported_versions": []} for name in sorted(evidence, key=str.casefold)]


def build_inventory(archive, root, sevenzip):
    version, entries = list_archive(sevenzip, archive)
    if any(e["encrypted"] for e in entries):
        raise ValueError("Encrypted outer members: password status unresolved")
    expected_files = {e["path"]: e for e in entries if not e["is_directory"]}
    expected_dirs = {e["path"] for e in entries if e["is_directory"]}
    top_levels = sorted({e["path"].split("/")[0] for e in entries})
    actual_files, actual_dirs = set(), set()
    for top in top_levels:
        location = root / top
        if not location.exists():
            raise ValueError(f"Missing extracted top level: {top}")
        for path in [location, *sorted(location.rglob("*"))] if location.is_dir() else [location]:
            info = path.lstat()
            if path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Extracted tree contains a link/reparse point")
            relative = path.relative_to(root).as_posix()
            (actual_dirs if path.is_dir() else actual_files).add(relative)
    if actual_files != set(expected_files) or actual_dirs != expected_dirs:
        raise ValueError("Extracted file/directory set differs from outer archive listing")
    files = []
    for name, entry in sorted(expected_files.items()):
        path = root / name
        data = path.read_bytes()
        crc = f"{zlib.crc32(data):08X}"
        if len(data) != entry["size"] or (entry["crc32"] and crc != entry["crc32"]):
            raise ValueError(f"Extracted size/CRC mismatch: {name}")
        suffix = path.suffix.lower()
        license_named = bool(re.fullmatch(r"(?i)(license|licence|copying|copyright)(\..*)?", path.name)) and suffix != ".key"
        record = {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                  "crc32": crc, "extension": suffix or "(none)",
                  "license_named_document": license_named,
                  "release_eligible": False, "license_status": "not_cleared_for_redistribution"}
        if data.startswith(b"MZ"):
            try:
                record["pe"] = PE(data).parse()
            except (ValueError, struct.error) as error:
                record["pe"] = {"format": "parse_error", "warnings": [str(error)]}
            record["strings"] = string_evidence(data)
            record["behavior_evidence"] = api_evidence(record["pe"], record["strings"])
        if suffix in TEXT_EXT | SOURCE_EXT or license_named:
            record["text"] = text_evidence(data)
        if suffix in SOURCE_EXT:
            record["source_candidate"] = True
        if suffix in ARCHIVE_EXT or data.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"PK\x03\x04")):
            record["nested_archive"] = nested_inventory(path, sevenzip)
        files.append(record)
    hashes = defaultdict(list)
    for file in files:
        hashes[file["sha256"]].append(file["path"])
    pe_files = [f for f in files if f.get("pe", {}).get("format") in {"PE32", "PE32+"}]
    families = family_evidence(files, root)
    inner_top = []
    if len(top_levels) == 1:
        prefix = top_levels[0] + "/"
        for entry in entries:
            if entry["path"].startswith(prefix) and "/" not in entry["path"][len(prefix):]:
                inner_top.append({"name": entry["path"][len(prefix):], "is_directory": entry["is_directory"]})
    nested = [f for f in files if "nested_archive" in f]
    summary = {
        "archive_entries": len(entries), "files": len(files), "directories_including_root": len(expected_dirs),
        "total_file_bytes": sum(f["size"] for f in files), "unique_sha256": len(hashes),
        "duplicate_groups": sum(len(paths) > 1 for paths in hashes.values()),
        "duplicate_extra_files": sum(len(paths) - 1 for paths in hashes.values()),
        "extensions": dict(sorted(Counter(f["extension"] for f in files).items())),
        "pe_files": len(pe_files), "pe_architectures": dict(sorted(Counter(f["pe"]["architecture"] for f in pe_files).items())),
        "pe_dll_flag": sum(f["pe"]["is_dll"] for f in pe_files),
        "pe_managed_clr_directory": sum(f["pe"]["managed_clr_directory"] for f in pe_files),
        "pe_with_version_resources": sum(bool(f["pe"].get("version_resources")) for f in pe_files),
        "pe_with_warnings": sum(bool(f["pe"]["warnings"]) for f in pe_files),
        "mz_non_pe_files": sum(f.get("pe", {}).get("format") == "MZ/non-PE" for f in files),
        "behavior_assessments": dict(sorted(Counter(f["behavior_evidence"]["assessment"] for f in files if "behavior_evidence" in f).items())),
        "text_files": sum("text" in f for f in files), "loose_source_files": sum(f.get("source_candidate", False) for f in files),
        "nested_archives": len(nested), "nested_source_members": sum(len(f["nested_archive"].get("source_members", [])) for f in nested),
        "probable_family_names": len(families), "inner_top_level_entries": len(inner_top),
        "inner_top_level_directories": sum(e["is_directory"] for e in inner_top),
        "inner_top_level_files": sum(not e["is_directory"] for e in inner_top),
        "cooldumpper_plugin_files": sum("/CoolDumpper/plugin/" in f["path"] for f in files),
        "families_only_in_bundled_claims": sum(all(e["basis"] == "bundled_author_claim_not_verified" for e in family["evidence"]) for family in families),
        "release_eligible_files": 0,
        "license_named_documents": sum(f["license_named_document"] for f in files),
    }
    unresolved = [{"path": f["path"], "status": f["nested_archive"]["status"],
                   "encrypted_members": f["nested_archive"].get("encrypted_members", [])}
                  for f in nested if f["nested_archive"]["status"] == "unresolved" or f["nested_archive"].get("encrypted_members")]
    return {
        "schema_version": 1, "method": "static bytes only; no extracted code executed; nested metadata only",
        "archive": {"name": archive.name, "size": archive.stat().st_size, "sha256": digest(archive),
                    "listing_tool": version, "unsafe_paths": [], "encrypted_entries": 0,
                    "top_level_names": top_levels, "entries": entries},
        "verification": {"exact_member_sets": True, "all_sizes_and_crc32_match_archive": True,
                         "file_sha256_recomputed": True, "unresolved_passwords_or_nested_listings": unresolved},
        "summary": summary, "inner_top_level": inner_top, "probable_families": families,
        "duplicates": [{"sha256": sha, "paths": paths} for sha, paths in sorted(hashes.items()) if len(paths) > 1],
        "limitations": [
            "File/tool/plugin/family counts do not establish supported versions or successful unpacking.",
            "Family evidence is normalized from tool/plugin names and one bundled author claims list, not signature matching.",
            "PE imports, delay imports, exports and RT_VERSION are statically parsed; malformed structures produce warnings.",
            "ASCII and ASCII-subset UTF-16LE string excerpts are bounded; API string presence is distinct from imports.",
            "Text encodings are guessed; identity/license excerpts are clues, not license clearance.",
            "Packed/obfuscated imports, runtime resolution, embedded payloads and CLR P/Invoke may hide behavior.",
            "Nested archives are listed once only; nested payload hashes, source contents and licenses are not inspected.",
            "PE architecture describes the tool binary, not the set of target architectures it supports.",
            "All reference payloads are excluded from release until their individual licenses and provenance are cleared.",
        ],
        "files": files,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True, help="Extraction destination containing archive top-level names")
    parser.add_argument("--sevenzip", type=Path, required=True, help="Trusted external 7-Zip, never an extracted copy")
    parser.add_argument("--output", type=Path, required=True, help="JSON output outside the archive's extracted top-level trees")
    parser.add_argument("--verify", action="store_true", help="Recompute and compare existing JSON; write nothing")
    parser.add_argument("--details", action="store_true", help="Print compact static research evidence after summary")
    args = parser.parse_args()
    root, sevenzip, output = args.root.resolve(), args.sevenzip.resolve(), args.output.resolve()
    if not root.is_dir() or not sevenzip.is_file() or not args.archive.is_file():
        parser.error("Archive, extracted root, and external 7-Zip must exist")
    if sevenzip.is_relative_to(root):
        parser.error("Refusing to execute a 7-Zip copy under the extracted root")
    if not output.parent.is_dir():
        parser.error("Output parent must already exist")
    try:
        result = build_inventory(args.archive, root, sevenzip)
        if any(output.is_relative_to(root / top) for top in result["archive"]["top_level_names"]):
            parser.error("Output must not overwrite extracted members or add files to their tree")
        if args.verify:
            previous = json.loads(output.read_text(encoding="utf-8"))
            if result != previous:
                raise ValueError("Verification failed: recomputed inventory differs from saved JSON")
            print("VERIFIED: archive listing, member sets, CRC32, SHA256, PE metadata and summary match")
        else:
            output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
        if args.details:
            print("FAMILIES: " + ", ".join(f["name"] for f in result["probable_families"]))
            print("DUPLICATES: " + json.dumps(result["duplicates"], ensure_ascii=False))
            for file in result["files"]:
                path = file["path"]
                pe = file.get("pe", {})
                if pe:
                    compact = {"path": path, "format": pe["format"], "arch": pe.get("architecture"),
                               "warnings": pe.get("warnings"), "assessment": file["behavior_evidence"]["assessment"]}
                    compact["apis"] = {k: v for k, v in file["behavior_evidence"]["groups"].items() if k in {"debugging", "remote_memory", "process_control", "decompression"} and (v["imports"] or v["strings_only"])}
                    compact["version"] = pe.get("version_resources")
                    if re.search(r"/(?i:upx|7z|demoleition)\.exe$", path):
                        compact["license_strings"] = file["strings"]["license_mentions"]
                    compact["exports"] = [name for e in pe.get("exports", {}).get("symbols", []) for name in e["names"]][:12]
                    if "/Universal Extractor/" not in path or pe.get("warnings") or re.search(r"/(?i:upx|aspackdie|7z|innounp)\.exe$", path):
                        print("PE " + json.dumps(compact, ensure_ascii=False))
                if "nested_archive" in file or file.get("source_candidate"):
                    print("SOURCE/ARCHIVE " + json.dumps(file, ensure_ascii=False))
                if "text" in file and "/Universal Extractor/" not in path:
                    print("TEXT " + json.dumps({"path": path, **file["text"]}, ensure_ascii=False))
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        print(f"Inventory failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
