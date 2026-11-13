# Building torwell (Arch/CachyOS)

Local/dev PKGBUILD; builds from the repository root.

Prerequisites: run `scripts/bootstrap-opentui.sh` once if `.tooling/` is missing.

Build:

    cd packaging/arch
    makepkg -s

Install the resulting package manually with `pacman -U` (not done by this task).

Do not enable the restore unit automatically; use `sudo torwell-engine boot-protection enable`.
