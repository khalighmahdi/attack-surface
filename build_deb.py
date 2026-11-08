#!/usr/bin/env python3
"""Build the Kali/Debian .deb without dpkg-deb (Arch-friendly).

Creates the exact deb structure: debian-binary + control.tar.gz + data.tar.gz
packed with `ar`, matching Debian binary package format.
"""
import gzip
import io
import os
import shutil
import subprocess
import sys
import tarfile

ROOT = os.path.dirname(os.path.abspath(__file__))
CONTROL = os.path.join(ROOT, "packaging/debian/DEBIAN/control")


def read_version() -> str:
    """Single source of truth: core/version.py (packaging control must match)."""
    ns: dict = {}
    with open(os.path.join(ROOT, "core", "version.py")) as f:
        exec(f.read(), ns)
    return ns["__version__"]


def build_deb(stage: str, out: str) -> None:
    # control.tar.gz (from DEBIAN/)
    def add_ctl(tf: tarfile.TarFile) -> None:
        ctl = os.path.join(stage, "DEBIAN")
        for name in sorted(os.listdir(ctl)):
            full = os.path.join(ctl, name)
            tf.add(full, arcname=f"./{name}", recursive=True)

    ctl_buf = io.BytesIO()
    with tarfile.open(fileobj=ctl_buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        add_ctl(tf)
    # data.tar.gz (everything except DEBIAN/), owner root
    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        for name in sorted(os.listdir(stage)):
            if name == "DEBIAN":
                continue
            full = os.path.join(stage, name)
            tf.add(full, arcname=f"./{name}", recursive=True)
    # ar archive
    with open(out, "wb") as f:
        f.write(b"!<arch>\n")
        for name, data in (
            ("debian-binary", b"2.0\n"),
            ("control.tar.gz", ctl_buf.getvalue()),
            ("data.tar.gz", data_buf.getvalue()),
        ):
            header = name.encode().ljust(16)[:16]
            f.write(header)
            f.write(b"0           ".ljust(12))          # mtime (0 = reproducible)
            f.write(b"0     ".ljust(6))                  # uid
            f.write(b"0     ".ljust(6))                  # gid
            f.write(b"100644  ".ljust(8))                # mode
            f.write(str(len(data)).encode().ljust(10))   # size
            f.write(b"\x60\x0a")                          # magic
            f.write(data)
            if len(data) % 2:
                f.write(b"\n")                            # 2-byte align


def main() -> None:
    version = read_version()
    stage = os.path.join(ROOT, f".stage-deb-{version}")
    out = os.path.join(ROOT, f"attack-surface_{version}_all.deb")

    if os.path.exists(stage):
        shutil.rmtree(stage)

    # layout (same as build-deb.sh)
    dirs = [
        "DEBIAN",
        "usr/share/attack-surface",
        "usr/share/man/man1",
        "usr/share/applications",
        "etc/bash_completion.d",
        "usr/bin",
    ]
    for d in dirs:
        os.makedirs(os.path.join(stage, d), exist_ok=True)

    # project files
    for item in ("core", "modules", "wordlists", "attack_surface.py",
                 "scanner.py", "db_store.py", "requirements.txt", "LICENSE", "README.md"):
        src = os.path.join(ROOT, item)
        dst = os.path.join(stage, "usr/share/attack-surface", item)
        if os.path.isdir(src):
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__"))
        elif os.path.exists(src):
            shutil.copy2(src, dst)

    # man page (gzipped)
    man_src = os.path.join(ROOT, "man/man1/attack-surface.1")
    with open(man_src, "rb") as fin:
        raw = fin.read()
    with open(os.path.join(stage, "usr/share/man/man1/attack-surface.1.gz"), "wb") as fout:
        fout.write(gzip.compress(raw, 9, mtime=0))

    # desktop + completion
    shutil.copy2(os.path.join(ROOT, "packaging/share/applications/attack-surface.desktop"),
                 os.path.join(stage, "usr/share/applications/"))
    shutil.copy2(os.path.join(ROOT, "packaging/share/bash-completion/completions/attack-surface"),
                 os.path.join(stage, "etc/bash_completion.d/"))

    # DEBIAN scripts
    for script in ("control", "postinst", "prerm"):
        shutil.copy2(os.path.join(ROOT, "packaging/debian/DEBIAN", script),
                     os.path.join(stage, "DEBIAN", script))
    # executable bits
    for script in ("postinst", "prerm"):
        os.chmod(os.path.join(stage, "DEBIAN", script), 0o755)
    os.chmod(os.path.join(stage, "usr/share/attack-surface/attack_surface.py"), 0o755)
    os.chmod(os.path.join(stage, "usr/share/attack-surface/scanner.py"), 0o755)

    build_deb(stage, out)
    shutil.rmtree(stage)
    size = os.path.getsize(out)
    print(f"== built: {out} ({size/1024:.0f} KB)")
    print("== install: sudo dpkg -i attack-surface_{0}_all.deb".format(version))
    print("== verify : dpkg-deb -I attack-surface_{0}_all.deb".format(version))


if __name__ == "__main__":
    main()
