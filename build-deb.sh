#!/bin/bash
# build-deb.sh — build a Kali/Debian .deb package for attack-surface
set -euo pipefail
VERSION=$(grep -oP '(?<=^Version: ).+' packaging/debian/DEBIAN/control)
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# layout
mkdir -p "$STAGE/DEBIAN" \
         "$STAGE/usr/share/attack-surface" \
         "$STAGE/usr/share/man/man1" \
         "$STAGE/usr/share/applications" \
         "$STAGE/etc/bash_completion.d"

# project files
cp -r core modules wordlists attack_surface.py scanner.py requirements.txt \
      "$STAGE/usr/share/attack-surface/"
cp man/man1/attack-surface.1 "$STAGE/usr/share/man/man1/"
gzip -9n "$STAGE/usr/share/man/man1/attack-surface.1"
cp packaging/share/applications/attack-surface.desktop "$STAGE/usr/share/applications/"
cp packaging/share/bash-completion/completions/attack-surface "$STAGE/etc/bash_completion.d/"
cp packaging/debian/DEBIAN/control "$STAGE/DEBIAN/"
cp packaging/debian/DEBIAN/postinst "$STAGE/DEBIAN/"
cp packaging/debian/DEBIAN/prerm "$STAGE/DEBIAN/"
cp LICENSE README.md "$STAGE/usr/share/attack-surface/"

# strip .git artifacts if any
find "$STAGE" -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true

dpkg-deb --build --root-owner-group "$STAGE" "attack-surface_${VERSION}_all.deb"
echo "== built: attack-surface_${VERSION}_all.deb"
echo "== install: sudo dpkg -i attack-surface_${VERSION}_all.deb"
