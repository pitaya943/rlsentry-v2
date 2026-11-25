"""Make a real Docker daemon and rlsentry's two pinned images ready, for the real-daemon tests.

Called once per session by `pytest --rlsentry-backend docker` (tests/conftest.py), and runnable
on its own: `python3 tests/realdocker.py`.

Why a helper in the repository and not the cloud environment's setup script: the setup script
runs only when a container is built fresh (after a resume the daemon is gone), may not start
background daemons, and is not versioned with the tests. This file is, and it does nothing on a
machine whose daemon already answers, such as a developer's laptop or a CI runner.

What it does, in order:
1. If `docker version` reaches a daemon, use it. Otherwise, only as root and only when `dockerd`
   is installed, start `dockerd` detached from this process (it outlives the test run, so the
   next run is fast), log to <tempdir>/rlsentry-dockerd.log, and wait up to 60 s for it.
   Anything else is a failure with its reason: the real-daemon tests then fail, never skip.
2. For each image rlsentry pins (rlsentry/backends/docker.py), if the tag is not present, pull
   it from Docker Hub, else from mirror.gcr.io, else from public.ecr.aws, and `docker tag` the
   mirror's copy under the pinned name, so rlsentry finds it and never pulls. Mirrors are
   trusted as caches of Docker Hub, the same trust rlsentry gives a tag; the image ID is
   printed so a run can be compared with another.

RLSENTRY_TEST_REFUSE_REGISTRY, a comma-separated list of registries (docker.io, mirror.gcr.io,
public.ecr.aws), makes this helper treat them as refusing, to show the fallback without waiting
for Docker Hub's rate limit.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from rlsentry.backends.docker import DB_IMAGE, REST_IMAGE  # noqa: E402  (the pinned names)

START_TIMEOUT = 60
LOG = Path(tempfile.gettempdir()) / "rlsentry-dockerd.log"

# Where each pinned image can be pulled from, in order. The ECR copy of PostgREST is Supabase's:
# there is no public.ecr.aws/postgrest repository, and Supabase's v12.2.3 has the same image ID
# as Docker Hub's (checked 2026-11-24, docs/tasks/real-docker/plan.md).
SOURCES = {
    DB_IMAGE: [("docker.io", DB_IMAGE),
               ("mirror.gcr.io", "mirror.gcr.io/library/postgres:16"),
               ("public.ecr.aws", "public.ecr.aws/docker/library/postgres:16")],
    REST_IMAGE: [("docker.io", REST_IMAGE),
                 ("mirror.gcr.io", "mirror.gcr.io/postgrest/postgrest:v12.2.3"),
                 ("public.ecr.aws", "public.ecr.aws/supabase/postgrest:v12.2.3")],
}


class NotReady(Exception):
    """The real daemon or an image cannot be made ready here; the message says why."""


def _docker(*args, timeout=60):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _last_line(text):
    lines = [line for line in (text or "").strip().splitlines() if line.strip()]
    return lines[-1] if lines else "(no output)"


def daemon_answers():
    try:
        return _docker("version", "--format", "{{.Server.Version}}", timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ensure_daemon(say=print):
    """Return a line saying which daemon is used; raise NotReady if none can answer."""
    if shutil.which("docker") is None:
        raise NotReady("no docker CLI on PATH")
    if daemon_answers():
        return f"using the Docker daemon already running ({_server_version()})"
    if os.environ.get("DOCKER_HOST"):
        raise NotReady(f"DOCKER_HOST={os.environ['DOCKER_HOST']} does not answer; "
                       "not starting a local daemon in its place")
    dockerd = shutil.which("dockerd")
    if dockerd is None:
        raise NotReady("no Docker daemon answers and dockerd is not installed")
    if os.geteuid() != 0:
        raise NotReady("no Docker daemon answers and starting dockerd needs root")
    say(f"starting dockerd (log: {LOG})")
    with open(LOG, "ab") as log:
        # A new session so that the daemon is not in pytest's process group: Ctrl-C on the
        # tests must not take the daemon down, and it is meant to outlive this run.
        subprocess.Popen([dockerd], stdout=log, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + START_TIMEOUT
    while time.monotonic() < deadline:
        if daemon_answers():
            return f"started dockerd ({_server_version()}), log: {LOG}"
        time.sleep(0.5)
    raise NotReady(f"dockerd did not answer within {START_TIMEOUT} s; "
                   f"last log line: {_last_line(LOG.read_text(errors='replace'))}")


def _server_version():
    return _docker("version", "--format", "{{.Server.Version}}").stdout.strip()


def _refused():
    return set(filter(None, os.environ.get("RLSENTRY_TEST_REFUSE_REGISTRY", "").split(",")))


def _image_id(ref):
    got = _docker("image", "inspect", "--format", "{{.Id}}", ref)
    return got.stdout.strip() if got.returncode == 0 else None


def ensure_image(image):
    """Make `image` present under its pinned name; return a line saying where it came from."""
    present = _image_id(image)
    if present:
        return f"{image}: already present ({present[:19]})"
    answers = []
    for registry, ref in SOURCES[image]:
        if registry in _refused():
            answers.append(f"{registry}: refused (RLSENTRY_TEST_REFUSE_REGISTRY)")
            continue
        pull = _docker("pull", ref, timeout=900)
        if pull.returncode != 0:
            answers.append(f"{registry}: {_last_line(pull.stderr)}")
            continue
        if ref != image:
            _docker("tag", ref, image).check_returncode()
        return f"{image}: pulled from {registry} ({_image_id(image)[:19]})"
    raise NotReady(f"cannot pull {image} from any registry:\n  " + "\n  ".join(answers))


def ensure(say=print):
    """Daemon, then both images. Return the lines describing what was done."""
    lines = [ensure_daemon(say)]
    for image in (DB_IMAGE, REST_IMAGE):
        lines.append(ensure_image(image))
    return lines


if __name__ == "__main__":
    try:
        for line in ensure():
            print(line)
    except NotReady as e:
        print(f"not ready: {e}", file=sys.stderr)
        sys.exit(1)
