#!/bin/bash
# Run a command in the T-03 worktree inside its own pid namespace and /tmp, so the machine-wide
# residue checks see only this run's processes (another builder runs rlsentry concurrently).
exec unshare --fork --pid --mount-proc --mount bash -c 'mount -t tmpfs -o mode=1777 tmpfs /tmp && cd "$0" && exec "$@"' /home/user/rlsentry-v2/.shilaycow/worktrees/T-03 "$@"
