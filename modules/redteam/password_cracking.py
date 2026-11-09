"""
Password Cracking & Hash Identification Module for Red Team Operations.

Wraps common cracking workflows (hashcat, John the Ripper) behind a unified
Python API and provides built-in hash identification, wordlist generation,
hash-file splitting, and rule browsing.  Pure stdlib — no third-party deps.

Typical usage:
    cracker = PasswordCracker()
    info = cracker.identify_hash("$2b$10$abcdef...")
    cmd = cracker.crack_hashcat(hash_file="hashes.txt", hash_info=info)
    wl = cracker.generate_wordlist(["admin", "corp"], numbers=True)
"""

from __future__ import annotations

import hashlib
import itertools
import os
import re
import string
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HashInfo:
    """Describes a recognised hash type."""

    hash_type: str
    mode_hashcat: int
    format_john: str
    description: str
    example: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hash_type": self.hash_type,
            "mode_hashcat": self.mode_hashcat,
            "format_john": self.format_john,
            "description": self.description,
            "example": self.example,
        }


# ---------------------------------------------------------------------------
# Hashcat mode reference (subset of popular modes)
# ---------------------------------------------------------------------------

HASHCAT_MODES: Dict[str, Dict[str, Any]] = {
    "MD5": {"mode": 0, "length": 32, "example": "5d41402abc4b2a76b9719d911017c592"},
    "MD5Crypt": {"mode": 500, "length": 34, "example": "$1$abc$hashvaluehere12"},
    "SHA1": {"mode": 100, "length": 40, "example": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"},
    "SHA256": {"mode": 1400, "length": 64, "example": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"},
    "SHA512": {"mode": 1700, "length": 128, "example": "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7"},
    "NTLM": {"mode": 1000, "length": 32, "example": "a4f49c406510bdcaab6c6d4d4f2e4af6"},
    "LM": {"mode": 3000, "length": 32, "example": "aad3b435b51404eeb0ac0ae57d3bf4a6"},
    "bcrypt": {"mode": 3200, "length": 60, "example": "$2b$10$N9qo8uLOickgx2ZMRZoMye..."},
    "MD4": {"mode": 900, "length": 32, "example": "c1c0f75e6b0c5e1a3d4e5f6a7b8c9d0e"},
    "RIPEMD160": {"mode": 6000, "length": 40, "example": "108f07b8382412612c048d07d13f814118445acd"},
    "Whirlpool": {"mode": 6100, "length": 128, "example": "0c3be7e6c72e4b6e3a6c5a7b8d9e0f1a2b3c4d5e"},
    "HMAC-MD5": {"mode": 150, "length": 32, "example": "63fb51f28e9a229e61e841090d2e5d46"},
    "HMAC-SHA1": {"mode": 160, "length": 40, "example": "0123456789abcdef0123456789abcdef01234567"},
    "HMAC-SHA256": {"mode": 1450, "length": 64, "example": "abcdef0123456789abcdef0123456789ab"},
    "Keccak-256": {"mode": 5000, "length": 64, "example": "7b3414e8..."},
}


# ---------------------------------------------------------------------------
# Hash identification patterns
# ---------------------------------------------------------------------------

_HASH_PATTERNS: List[Tuple[str, re.Pattern[str], str, int, str]] = [
    # (hash_type, compiled_regex, john_format, hashcat_mode, description)
    (
        "bcrypt",
        re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$"),
        "bcrypt",
        3200,
        "BCrypt password hash",
    ),
    (
        "MD5Crypt",
        re.compile(r"^\$1\$[^\$]{8}\$[./A-Za-z0-9]{22}$"),
        "md5crypt",
        500,
        "MD5-based crypt (FreeBSD/Linux)",
    ),
    (
        "SHA512Crypt",
        re.compile(r"^\$6\$[^\$]{8}\$[./A-Za-z0-9]{86}$"),
        "sha512crypt",
        1800,
        "SHA-512 crypt (modern Linux)",
    ),
    (
        "NTLM",
        re.compile(r"^[a-fA-F0-9]{32}$"),
        "NT",
        1000,
        "Windows NTLM hash (16 bytes hex)",
    ),
    (
        "MD5",
        re.compile(r"^[a-fA-F0-9]{32}$"),
        "raw-md5",
        0,
        "MD5 hash (16 bytes hex)",
    ),
    (
        "SHA1",
        re.compile(r"^[a-fA-F0-9]{40}$"),
        "raw-sha1",
        100,
        "SHA-1 hash (20 bytes hex)",
    ),
    (
        "SHA256",
        re.compile(r"^[a-fA-F0-9]{64}$"),
        "raw-sha256",
        1400,
        "SHA-256 hash (32 bytes hex)",
    ),
    (
        "SHA512",
        re.compile(r"^[a-fA-F0-9]{128}$"),
        "raw-sha512",
        1700,
        "SHA-512 hash (64 bytes hex)",
    ),
    (
        "RIPEMD160",
        re.compile(r"^[a-fA-F0-9]{40}$"),
        "ripemd160",
        6000,
        "RIPEMD-160 hash (20 bytes hex)",
    ),
    (
        "MySQL4.1+",
        re.compile(r"^\*[a-fA-F0-9]{40}$"),
        "mysql-sha1",
        300,
        "MySQL 4.1+ password hash (* prefix)",
    ),
    (
        "MSSQL_2005",
        re.compile(r"^0x0100[0-9a-fA-F]{8}[0-9a-fA-F]{40}$"),
        "mssql05",
        1731,
        "MS SQL Server 2005 hash",
    ),
]


# ---------------------------------------------------------------------------
# John the Ripper format list
# ---------------------------------------------------------------------------

JOHN_FORMATS: List[Dict[str, str]] = [
    {"name": "raw-md5", "description": "Raw MD5"},
    {"name": "raw-sha1", "description": "Raw SHA-1"},
    {"name": "raw-sha256", "description": "Raw SHA-256"},
    {"name": "raw-sha512", "description": "Raw SHA-512"},
    {"name": "md5crypt", "description": "MD5 crypt (BSD)"},
    {"name": "sha256crypt", "description": "SHA-256 crypt"},
    {"name": "sha512crypt", "description": "SHA-512 crypt"},
    {"name": "bcrypt", "description": "BCrypt"},
    {"name": "NT", "description": "Windows NTLM"},
    {"name": "LM", "description": "Windows LM"},
    {"name": "descrypt", "description": "traditional DES crypt"},
    {"name": "netntlmv2", "description": "NTLMv2 network auth"},
    {"name": "mssql05", "description": "MS SQL Server 2005"},
    {"name": "oracle11", "description": "Oracle 11g"},
    {"name": "sha3_256", "description": "SHA3-256"},
    {"name": "argon2", "description": "Argon2"},
]


# ---------------------------------------------------------------------------
# Hashcat rule sets
# ---------------------------------------------------------------------------

HASHCAT_RULES: Dict[str, List[str]] = {
    "best64.rule": [
        ":",  # do nothing
        "l",  # lowercase
        "u",  # uppercase
        "c",  # capitalize
        "r",  # reverse
        "d",  # duplicate
        "t",  # toggle case of all chars",
        "tn",  # toggle nth char",
        "An",  # append char n",
        "Dn",  # delete char n",
        "sn",  # purge char n",
        "sa$1",  # append '1'",
        "$1$",  # prepend '1'",
    ],
    "d3ad0ne.rule": [
        ":",
        "l",
        "u",
        "c",
        "r",
        "d",
        "$1$",
        "$2$",
        "$3$",
        "sa@",
        "so0",
        "si!",
        "se3",
    ],
    "rockyou-30000.rule": [
        ":",
        "l",
        "u",
        "c",
        "r",
        "d",
        "$!",
        "$1",
        "$2",
        "$@",
        "^1^",
        "sa@",
        "so0",
        "^$a",
    ],
    "one.rule": [
        ":",
        "l",
    ],
    "toggles1.rule": [
        "t0",
        "t1",
        "t2",
        "t3",
        "t4",
    ],
}


# ---------------------------------------------------------------------------
# Main cracker class
# ---------------------------------------------------------------------------

class PasswordCracker:
    """High-level interface around hashcat and John the Ripper."""

    def __init__(
        self,
        hashcat_bin: str = "hashcat",
        john_bin: str = "john",
    ) -> None:
        self.hashcat_bin = hashcat_bin
        self.john_bin = john_bin

    # -- hash identification ------------------------------------------------

    def identify_hash(self, hash_value: str) -> HashInfo:
        """Identify a hash by pattern matching.

        Tries known prefix patterns first, then falls back to length-based
        heuristics.  Returns a HashInfo with best-guess metadata.
        """
        cleaned = hash_value.strip()

        # Pattern-based identification
        for name, pattern, john_fmt, hc_mode, desc in _HASH_PATTERNS:
            if pattern.match(cleaned):
                return HashInfo(
                    hash_type=name,
                    mode_hashcat=hc_mode,
                    format_john=john_fmt,
                    description=desc,
                    example=cleaned[:40] + ("..." if len(cleaned) > 40 else ""),
                )

        # Length-based fallback
        hex_only = cleaned.lstrip("$").lstrip("*")
        if re.match(r"^[a-fA-F0-9]+$", hex_only):
            hlen = len(hex_only)
            if hlen == 32:
                return HashInfo("MD5 (likely)", 0, "raw-md5",
                                "32-char hex — probable MD5 or NTLM")
            if hlen == 40:
                return HashInfo("SHA-1 (likely)", 100, "raw-sha1",
                                "40-char hex — probable SHA-1")
            if hlen == 64:
                return HashInfo("SHA-256 (likely)", 1400, "raw-sha256",
                                "64-char hex — probable SHA-256")
            if hlen == 128:
                return HashInfo("SHA-512 (likely)", 1700, "raw-sha512",
                                "128-char hex — probable SHA-512")

        # Unknown
        return HashInfo(
            hash_type="unknown",
            mode_hashcat=0,
            format_john="raw-md5",
            description="Could not identify hash — manual analysis required",
        )

    def identify_hash_file(self, path: str) -> List[HashInfo]:
        """Identify every hash in a file (one hash per line)."""
        results: List[HashInfo] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        results.append(self.identify_hash(line))
        except FileNotFoundError:
            pass
        return results

    # -- cracking wrappers --------------------------------------------------

    def crack_hashcat(
        self,
        hash_file: str,
        hash_info: Optional[HashInfo] = None,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        rules: Optional[str] = None,
        attack_mode: int = 0,
        extra_args: Optional[List[str]] = None,
        session_name: str = "session1",
    ) -> str:
        """Build and (optionally) execute a hashcat command string.

        Returns the command that *would* be executed.  Actual execution
        is opt-in so the caller can review before running.
        """
        if hash_info is None:
            raise ValueError("hash_info must be provided for crack_hashcat")

        cmd: List[str] = [
            self.hashcat_bin,
            "-m", str(hash_info.mode_hashcat),
            "-a", str(attack_mode),
            "--session", session_name,
        ]

        if rules:
            cmd.extend(["-r", rules])

        if extra_args:
            cmd.extend(extra_args)

        cmd.extend([hash_file, wordlist])
        return " ".join(cmd)

    def crack_john(
        self,
        hash_file: str,
        hash_info: Optional[HashInfo] = None,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        extra_args: Optional[List[str]] = None,
    ) -> str:
        """Build a John the Ripper command string."""
        cmd: List[str] = [self.john_bin]

        if hash_info:
            cmd.extend(["--format=" + hash_info.format_john])

        if extra_args:
            cmd.extend(extra_args)

        cmd.extend(["--wordlist=" + wordlist, hash_file])
        return " ".join(cmd)

    def crack_john_incremental(
        self,
        hash_file: str,
        hash_info: Optional[HashInfo] = None,
        extra_args: Optional[List[str]] = None,
    ) -> str:
        """Build a John incremental-mode command."""
        cmd: List[str] = [self.john_bin, "--incremental"]
        if hash_info:
            cmd.extend(["--format=" + hash_info.format_john])
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(hash_file)
        return " ".join(cmd)

    def crack_john_rules(
        self,
        hash_file: str,
        hash_info: Optional[HashInfo] = None,
        wordlist: str = "/usr/share/wordlists/rockyou.txt",
        rules: str = "best64",
    ) -> str:
        """Build a John command with rules."""
        cmd: List[str] = [self.john_bin]
        if hash_info:
            cmd.extend(["--format=" + hash_info.format_john])
        cmd.extend(["--wordlist=" + wordlist, "--rules=" + rules, hash_file])
        return " ".join(cmd)

    # -- wordlist generation ------------------------------------------------

    def generate_wordlist(
        self,
        base_words: List[str],
        numbers: bool = False,
        leet: bool = False,
        years: bool = False,
        special: bool = False,
        max_length: int = 16,
        output_file: Optional[str] = None,
    ) -> List[str]:
        """Generate a mutated wordlist from base words.

        Mutations:
          - lowercase / uppercase / capitalised variants
          - leet-speak substitution (a->4, e->3, i->1, o->0, s->$)
          - appended years (2020-2025) and digits (0-99)
          - appended special chars (!, @, #, $)

        Returns the wordlist in memory and optionally writes to disk.
        """
        words: Set[str] = set()

        for w in base_words:
            variants = {
                w.lower(),
                w.upper(),
                w.capitalize(),
                w.title(),
            }
            for v in variants:
                words.add(v)
                if leet:
                    words.add(self._to_leet(v))
                if numbers:
                    for num in range(0, 100):
                        cand = v + str(num)
                        if len(cand) <= max_length:
                            words.add(cand)
                        cand2 = str(num) + v
                        if len(cand2) <= max_length:
                            words.add(cand2)
                if years:
                    for year in range(2015, 2026):
                        cand = v + str(year)
                        if len(cand) <= max_length:
                            words.add(cand)
                if special:
                    for ch in "!@#$%^&*":
                        cand = v + ch
                        if len(cand) <= max_length:
                            words.add(cand)
                        cand2 = ch + v
                        if len(cand2) <= max_length:
                            words.add(cand2)

        wordlist = sorted(w for w in words if len(w) <= max_length)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as fh:
                for w in wordlist:
                    fh.write(w + "\n")

        return wordlist

    def generate_wordlist_from_names(
        self,
        first_names: List[str],
        last_names: List[str],
        company: str = "",
        output_file: Optional[str] = None,
    ) -> List[str]:
        """Create a targeted wordlist from employee names."""
        patterns: List[str] = []
        for first in first_names:
            fl = first.lower()
            patterns.append(fl)
            patterns.append(fl.capitalize())
        for last in last_names:
            ll = last.lower()
            patterns.append(ll)
            patterns.append(ll.capitalize())

        combos: Set[str] = set()
        for f in first_names:
            for l in last_names:
                fl, ll = f.lower(), l.lower()
                for sep in ("", ".", "_", "-"):
                    combos.add(fl + sep + ll)
                    combos.add(ll + sep + fl)
                    combos.add(f[0].lower() + ll)
                    combos.add(fl + ll[0].lower())

        if company:
            cl = company.lower()
            for f in first_names:
                combos.add(f.lower() + cl)
                combos.add(cl + f.lower())
            for l in last_names:
                combos.add(l.lower() + cl)
                combos.add(cl + l.lower())

        wordlist = sorted(set(patterns) | combos)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as fh:
                for w in wordlist:
                    fh.write(w + "\n")

        return wordlist

    # -- hash file splitting ------------------------------------------------

    def split_hash_file(
        self,
        input_file: str,
        lines_per_chunk: int = 10_000,
        output_dir: str = "./chunks",
    ) -> List[str]:
        """Split a large hash file into smaller chunks for parallel cracking.

        Returns the list of output file paths.
        """
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        output_paths: List[str] = []
        chunk_idx = 0

        try:
            with open(input_file, "r", encoding="utf-8", errors="replace") as fh:
                lines: List[str] = []
                for line in fh:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        lines.append(stripped)
                        if len(lines) >= lines_per_chunk:
                            out_path = os.path.join(
                                output_dir, f"chunk_{chunk_idx:04d}.txt"
                            )
                            self._write_lines(out_path, lines)
                            output_paths.append(out_path)
                            chunk_idx += 1
                            lines = []
                # flush remaining
                if lines:
                    out_path = os.path.join(
                        output_dir, f"chunk_{chunk_idx:04d}.txt"
                    )
                    self._write_lines(out_path, lines)
                    output_paths.append(out_path)
        except FileNotFoundError:
            pass

        return output_paths

    # -- rules display ------------------------------------------------------

    def show_rules(self, rule_set: Optional[str] = None) -> List[str]:
        """Return rules from the built-in rule dictionary.

        If *rule_set* is None, return all available rule-set names.
        """
        if rule_set is None:
            return list(HASHCAT_RULES.keys())
        return HASHCAT_RULES.get(rule_set, [])

    def list_john_formats(self) -> List[Dict[str, str]]:
        """Return the built-in John format reference list."""
        return list(JOHN_FORMATS)

    def list_hashcat_modes(self) -> List[Dict[str, Any]]:
        """Return the built-in hashcat mode reference."""
        result: List[Dict[str, Any]] = []
        for name, info in HASHCAT_MODES.items():
            result.append({"hash_type": name, **info})
        return result

    # -- batch analysis -----------------------------------------------------

    def analyse_hash_file(self, path: str) -> Dict[str, Any]:
        """Analyse a hash file: identify types, count, split recommendations."""
        infos = self.identify_hash_file(path)
        counts: Dict[str, int] = {}
        for info in infos:
            counts[info.hash_type] = counts.get(info.hash_type, 0) + 1

        total = len(infos)
        recommended_chunk_size = 10_000
        if total > 100_000:
            recommended_chunk_size = 25_000
        elif total < 1_000:
            recommended_chunk_size = total

        return {
            "total_hashes": total,
            "hash_types": counts,
            "recommended_chunk_size": recommended_chunk_size,
            "suggested_chunks": max(1, total // recommended_chunk_size),
        }

    # -- utility ------------------------------------------------------------

    @staticmethod
    def _to_leet(word: str) -> str:
        """Convert common letters to leet-speak."""
        mapping = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
        return "".join(mapping.get(c.lower(), c) for c in word)

    @staticmethod
    def _write_lines(path: str, lines: List[str]) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")

    @staticmethod
    def compute_hash(text: str, algorithm: str = "md5") -> str:
        """Utility: hash a plaintext with the specified algorithm."""
        algo_map = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }
        fn = algo_map.get(algorithm.lower())
        if fn is None:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        return fn(text.encode("utf-8")).hexdigest()
