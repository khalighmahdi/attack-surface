#!/usr/bin/env bash
# Local release helper (tag + build + announce)
set -e
VER=$(python3 -c "exec(open('core/version.py').read()); print(__version__)")
echo "Releasing v$VER"
# git tag -a "v$VER" -m "Release v$VER"
# git push origin "v$VER"
# python build_deb.py
# docker build -t attack-surface:$VER .
