# Changelog

## v0.23.0 (2026-11-10)
### Added
- MCP presets (`--fast`, `--redteam-safe`), MCP `run_scan` flags for them
- Animated dashboard skin (CSS keyframes) and operations console polish
- AUR packaging (`packaging/aur/PKGBUILD`, `.SRCINFO`)
- `SECURITY.md`, `CONTRIBUTING.md`, AUR install instructions
- Dalfox in Kali Docker image
- parallel admin panel / CMS setup detection + longer-run stability

### Changed
- Renamed LLM env vars to `ATTACK_SURFACE_LLM_*` (legacy still supported)
- Version single-source `0.23.0`

### Fixed
- `check_leaks` false positives (soft-404, 403)
- `web_misconfig` / `admin_finder` / `setup_page_detector` phase hangs

## v0.22.0 (2026-11-09)
- Added MCP server (5 tools) and OpenCode skill
- Hardened open-source tree (clean git history, removed artifacts)
- Expanded English README
