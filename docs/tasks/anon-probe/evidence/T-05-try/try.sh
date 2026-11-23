#!/bin/bash
# Drive --backend the way a user does, here (no Docker daemon), then on tests/fakedocker.py.
# Usage, from the checkout root with rlsentry installed (pip install -e .):
#   bash docs/tasks/anon-probe/evidence/T-05-try/try.sh > docs/tasks/anon-probe/evidence/T-05-try/transcript.txt 2>&1
export RLSENTRY_STATE_DIR="$(mktemp -d)"
step() { echo "\$ $*"; "$@"; echo "[exit $?]"; echo; }
step rlsentry attack --help
step docker version --format '{{.Server.Version}}'
step rlsentry attack --migrations tests/fixtures/clean
step rlsentry attack --backend docker --migrations tests/fixtures/clean
step rlsentry attack --backend local --migrations tests/fixtures/clean

echo "### the same commands with tests/fakedocker.py as the docker CLI and daemon"
fake="$(mktemp -d)"; mkdir "$fake/bin" "$fake/docker"
printf '#!/bin/sh\nexec python3 %s "$@"\n' "$PWD/tests/fakedocker.py" > "$fake/bin/docker"; chmod +x "$fake/bin/docker"
export PATH="$fake/bin:$PATH" FAKE_DOCKER_DIR="$fake/docker"
step rlsentry attack --lab
echo "docker run calls made by that run:"
grep '^\["run"' "$fake/docker/calls.jsonl" | python3 -c 'import json,sys; [print("  docker " + " ".join(json.loads(l))) for l in sys.stdin]'
step docker ps -a --filter label=rlsentry.run
echo "### images not present, and Docker Hub answers 429"
rm "$fake/docker/state.json"
FAKE_DOCKER_FAIL=pull step rlsentry attack --migrations tests/fixtures/clean
FAKE_DOCKER_FAIL=pull step rlsentry attack --backend docker --migrations tests/fixtures/clean
FAKE_DOCKER_FAIL=rest-run step rlsentry attack --backend docker --migrations tests/fixtures/clean
step docker ps -a --filter label=rlsentry.run
rm -rf "$fake" "$RLSENTRY_STATE_DIR"
