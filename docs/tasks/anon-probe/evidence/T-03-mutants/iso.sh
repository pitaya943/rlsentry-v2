#!/bin/bash
# Run a command at the root of this checkout inside its own pid namespace and /tmp, so the
# machine-wide residue checks see only this run's processes (another rlsentry run may share
# the machine). Needs root (unshare). Usage: iso.sh python3 -m pytest -q
root="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)" || exit 2
exec unshare --fork --pid --mount-proc --mount bash -c 'mount -t tmpfs -o mode=1777 tmpfs /tmp && cd "$0" && exec "$@"' "$root" "$@"
