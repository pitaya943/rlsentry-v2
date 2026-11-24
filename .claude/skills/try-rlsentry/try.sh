#!/usr/bin/env bash
# Drive rlsentry as a user does; record everything under the evidence dir given as $1.
set -u
out="${1:?usage: try.sh <evidence-dir>}"
mkdir -p "$out"
log="$out/transcript.txt"
: > "$log"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0

residue() {
  { ls -d /tmp/rlsentry-run-* 2>/dev/null; pgrep -af 'rlsentry-run-|^postgres|postgresql/[0-9]+/bin' ; } | sort
}

step() {  # step <expected-exit> <command...>
  local want="$1"; shift
  echo "\$ $*" >> "$log"
  "$@" >> "$log" 2>&1
  local got=$?
  echo "[exit $got, expected $want]" >> "$log"; echo >> "$log"
  if [ "$got" != "$want" ]; then echo "FAIL: $* exited $got, expected $want" | tee -a "$log"; fail=1; fi
}

before="$(residue)"
step 1 rlsentry attack --lab
rlsentry attack --lab --json > "$out/report.json" 2>> "$log"; echo "[--json exit $?]" >> "$log"

mkdir "$work/clean"
cat > "$work/clean/001_profiles.sql" <<'SQL'
create table profiles (id bigint generated always as identity primary key, email text not null);
alter table profiles enable row level security;
SQL
step 0 rlsentry attack --migrations "$work/clean"

fixtures="$(cd "$(dirname "$0")/../../../tests/fixtures" && pwd)"
step 1 rlsentry attack --migrations "$fixtures/supabase_app"
step 2 rlsentry attack --migrations "$fixtures/broken"
step 2 rlsentry attack --migrations "$fixtures/unseedable_point"

step 2 rlsentry attack --target https://x.supabase.co

victim="$(mktemp -d)"; chmod 777 "$victim"  # writable by the server's OS user: only privileges stop it
mkdir "$work/host"
cat > "$work/host/001_host.sql" <<SQL
create table t (id bigint generated always as identity primary key);
copy (select 1) to program 'touch $victim/pwned';
SQL
step 2 rlsentry attack --migrations "$work/host"
if [ -e "$victim/pwned" ]; then echo "FAIL: a migration reached the host" | tee -a "$log"; fail=1
else echo "host untouched: $victim/pwned does not exist" >> "$log"; fi
rm -rf "$victim"

mkdir "$work/slow"
cat > "$work/slow/001_slow.sql" <<'SQL'
create table slow (id bigint generated always as identity primary key, note text);
alter table slow enable row level security;
create policy "slow read" on slow for select to anon using ((select true from pg_sleep(30)));
SQL
echo "\$ rlsentry attack --migrations slow   # then Ctrl-C (SIGINT) mid-attack" >> "$log"
rlsentry attack --migrations "$work/slow" >> "$log" 2>&1 &
pid=$!
for _ in $(seq 100); do pgrep -f "postgrest .*rlsentry-run-" > /dev/null && break; sleep 0.1; done
sleep 1
echo "during run: $(pgrep -fc 'rlsentry-run-') process(es) naming a run dir" >> "$log"
kill -INT "$pid"; wait "$pid"; got=$?
echo "[exit $got, expected 2]" >> "$log"
[ "$got" = 2 ] || { echo "FAIL: interrupted run exited $got" | tee -a "$log"; fail=1; }

after="$(residue)"
{ echo; echo "residue before: ${before:-none}"; echo "residue after:  ${after:-none}"; } >> "$log"
[ "$before" = "$after" ] || { echo "FAIL: residue changed" | tee -a "$log"; fail=1; }
[ "$fail" = 0 ] && echo "all steps as expected" | tee -a "$log"
exit "$fail"
