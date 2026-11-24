set -u
w=$(mktemp -d); export RLSENTRY_STATE_DIR=$w/state
fake=$w/fake; mkdir -p $fake/bin $fake/docker
printf '#!/bin/sh\nexec python3 %s "$@"\n' "$PWD/tests/fakedocker.py" > $fake/bin/docker; chmod +x $fake/bin/docker
export PATH="$fake/bin:$PATH" FAKE_DOCKER_DIR=$fake/docker
probe() { name=$1; sql=$2; mkdir -p $w/$name; printf '%s\n' "$sql" > $w/$name/001.sql
  for b in local docker; do echo "\$ rlsentry attack --backend $b --migrations <$name>"; echo "  ($sql)"
    rlsentry attack --backend $b --migrations $w/$name 2>&1 | tail -3; echo "[exit ${PIPESTATUS[0]}]"; echo; done; }
probe read-log "select pg_read_binary_file(pg_current_logfile('jsonlog'));"
probe read-log-by-name "select pg_read_binary_file('log/' || f) from pg_ls_logdir() f;"
probe turn-off-log "alter system set log_destination = 'stderr';"
probe grant-reader "grant pg_read_server_files to postgres;"
echo "residue: $(ls -d /tmp/rlsentry-run-* 2>/dev/null; docker ps -a -q)"
rm -rf $w
