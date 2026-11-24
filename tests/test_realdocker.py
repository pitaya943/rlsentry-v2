"""The real-Docker test tooling (brief real-docker S-1, S-2, S-3, S-8).

Starting a daemon and falling back to a mirror are shown twice: with stub `docker` and
`dockerd` programs that record what they are asked (here every path, including "no daemon
yet" and "Docker Hub refuses", can be forced and runs on any backend), and on the real daemon
(marked `real_docker`). Which tests run under which option is shown by running pytest itself.
"""

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import conftest
import realdocker
from rlsentry.backends.docker import DB_IMAGE, REST_IMAGE

TESTS = Path(__file__).parent

# A stand-in for the docker CLI with just what the helper uses. It records each argv in
# $STUB_DIR/calls.jsonl. The daemon answers once $STUB_DIR/up exists (the stub dockerd creates
# it); `pull` fails with Docker Hub's 429 for docker.io names and for any registry listed in
# $STUB_DIR/down; `image inspect` finds what was pulled or tagged.
STUB_DOCKER = textwrap.dedent('''\
    import json, os, sys
    from pathlib import Path
    d = Path(os.environ["STUB_DIR"])
    args = sys.argv[1:]
    with open(d / "calls.jsonl", "a") as f:
        f.write(json.dumps(["docker", *args]) + "\\n")
    images = d / "images.json"
    have = json.loads(images.read_text()) if images.exists() else {}
    down = (d / "down").read_text().split(",") if (d / "down").exists() else []
    if not (d / "up").exists():
        sys.exit("Cannot connect to the Docker daemon at unix:///var/run/docker.sock.")
    if args[0] == "version":
        print("99.0-stub")
    elif args[:2] == ["image", "inspect"]:
        ref = args[-1]
        if ref not in have:
            sys.exit(f"Error: No such image: {ref}")
        print(have[ref])
    elif args[0] == "pull":
        ref = args[1]
        registry = ref.split("/")[0] if "." in ref.split("/")[0] else "docker.io"
        if registry == "docker.io" or registry in down:
            sys.exit(f"Error response from daemon: {registry}: 429 Too Many Requests")
        have[ref] = "sha256:" + ("a" if "postgres" in ref else "b") * 64
    elif args[0] == "tag":
        have[args[2]] = have[args[1]]
    images.write_text(json.dumps(have))
''')

STUB_DOCKERD = textwrap.dedent('''\
    import json, os
    from pathlib import Path
    d = Path(os.environ["STUB_DIR"])
    with open(d / "calls.jsonl", "a") as f:
        f.write(json.dumps(["dockerd"]) + "\\n")
    (d / "up").touch()
''')


@pytest.fixture
def stub(tmp_path, monkeypatch):
    """Stub docker and dockerd first on PATH; returns the stub's state directory."""
    bin_dir, state = tmp_path / "bin", tmp_path / "stub"
    bin_dir.mkdir()
    state.mkdir()
    for name, code in (("docker", STUB_DOCKER), ("dockerd", STUB_DOCKERD)):
        (bin_dir / f"{name}.py").write_text(code)
        (bin_dir / name).write_text(f'#!/bin/sh\nexec {sys.executable} {bin_dir / name}.py "$@"\n')
        (bin_dir / name).chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("STUB_DIR", str(state))
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("RLSENTRY_TEST_REFUSE_REGISTRY", raising=False)
    monkeypatch.setattr(realdocker, "LOG", tmp_path / "dockerd.log")
    monkeypatch.setattr(realdocker.os, "geteuid", lambda: 0)
    return state


def _calls(state):
    path = state / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


# S-1: a daemon is brought up when none answers, once.

def test_starts_dockerd_when_no_daemon_answers_and_reuses_it_after(stub):
    first = realdocker.ensure_daemon()
    second = realdocker.ensure_daemon()

    assert first.startswith("started dockerd") and str(realdocker.LOG) in first
    assert second.startswith("using the Docker daemon already running")
    assert [c for c in _calls(stub) if c[0] == "dockerd"] == [["dockerd"]]


@pytest.mark.parametrize("why, setup", [
    ("starting dockerd needs root", lambda mp: mp.setattr(realdocker.os, "geteuid", lambda: 1000)),
    ("dockerd is not installed", lambda mp: mp.setattr(
        realdocker.shutil, "which", lambda name: None if name == "dockerd" else "/x/docker")),
    ("does not answer; not starting", lambda mp: mp.setenv("DOCKER_HOST", "tcp://10.0.0.9:2375")),
])
def test_does_not_start_dockerd_where_it_should_not_and_says_why(stub, monkeypatch, why, setup):
    setup(monkeypatch)
    with pytest.raises(realdocker.NotReady, match=why):
        realdocker.ensure_daemon()
    assert [c for c in _calls(stub) if c[0] == "dockerd"] == []


def test_gives_up_on_a_dockerd_that_never_answers(stub, monkeypatch):
    monkeypatch.setattr(realdocker, "START_TIMEOUT", 1)
    (stub.parent / "bin" / "dockerd.py").write_text("print('failed to start daemon: boom')\n")
    with pytest.raises(realdocker.NotReady, match="did not answer within 1 s"):
        realdocker.ensure_daemon()


# S-3: images come from a mirror when Docker Hub refuses.

def test_pulls_from_mirror_gcr_when_docker_hub_refuses_and_tags_the_pinned_name(stub):
    (stub / "up").touch()

    said = [realdocker.ensure_image(DB_IMAGE), realdocker.ensure_image(REST_IMAGE)]

    assert said[0].startswith(f"{DB_IMAGE}: pulled from mirror.gcr.io")
    assert said[1].startswith(f"{REST_IMAGE}: pulled from mirror.gcr.io")
    pulls = [c[2] for c in _calls(stub) if c[1] == "pull"]
    assert pulls == [DB_IMAGE, "mirror.gcr.io/library/postgres:16",
                     REST_IMAGE, "mirror.gcr.io/postgrest/postgrest:v12.2.3"]
    assert ["docker", "tag", "mirror.gcr.io/library/postgres:16", DB_IMAGE] in _calls(stub)
    assert realdocker.ensure_image(DB_IMAGE).startswith(f"{DB_IMAGE}: already present")


def test_falls_back_to_public_ecr_when_mirror_gcr_refuses_too(stub):
    (stub / "up").touch()
    (stub / "down").write_text("mirror.gcr.io")

    said = realdocker.ensure_image(REST_IMAGE)

    assert said.startswith(f"{REST_IMAGE}: pulled from public.ecr.aws")
    assert ["docker", "tag", "public.ecr.aws/supabase/postgrest:v12.2.3", REST_IMAGE] in _calls(stub)


def test_names_every_registry_when_all_refuse(stub, monkeypatch):
    (stub / "up").touch()
    (stub / "down").write_text("mirror.gcr.io")
    monkeypatch.setenv("RLSENTRY_TEST_REFUSE_REGISTRY", "public.ecr.aws")

    with pytest.raises(realdocker.NotReady) as e:
        realdocker.ensure_image(DB_IMAGE)

    said = str(e.value)
    assert "docker.io: Error response from daemon: docker.io: 429 Too Many Requests" in said
    assert "mirror.gcr.io: Error response from daemon: mirror.gcr.io: 429" in said
    assert "public.ecr.aws: refused (RLSENTRY_TEST_REFUSE_REGISTRY)" in said


# Which tests run under which option, shown by running pytest on the real-daemon lab test.

def _pytest(*args, env=None):
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-rsf",
         str(TESTS / "test_docker.py"), "-k", "real_docker_daemon", *args],
        capture_output=True, text=True, timeout=600, env=env, cwd=TESTS.parent)


@pytest.mark.parametrize("option", [[], ["--rlsentry-backend", "fakedocker"]])
def test_without_the_docker_option_real_tests_skip_and_no_daemon_or_pull_is_asked_for(
        stub, option):
    """S-8 (and S-7's "not against the stand-in"): even with a daemon answering, the default
    command and the stand-in option skip the real-daemon tests and ask Docker for nothing."""
    (stub / "up").touch()

    run = _pytest(*option, env=dict(os.environ))

    assert run.returncode == 0, run.stdout + run.stderr
    assert "1 skipped" in run.stdout
    assert conftest.REAL_DOCKER_COMMAND in run.stdout
    assert [c for c in _calls(stub) if c[0] == "dockerd" or c[1:2] == ["pull"]] == []


def test_with_the_docker_option_a_daemon_that_cannot_answer_fails_the_real_tests(stub):
    """S-2: not root, no daemon -> the real-daemon test fails with the reason; never a skip."""
    env = dict(os.environ, DOCKER_HOST="unix:///nonexistent/docker.sock")

    run = _pytest("--rlsentry-backend", "docker", env=env)

    assert run.returncode == 1, run.stdout + run.stderr
    assert "1 failed" in run.stdout and "skipped" not in run.stdout
    assert "the real Docker daemon is not ready" in run.stdout
    assert "DOCKER_HOST=unix:///nonexistent/docker.sock does not answer" in run.stdout
    assert [c for c in _calls(stub) if c[0] == "dockerd"] == []


# On the real daemon.

@pytest.mark.real_docker
def test_the_real_daemon_answered_before_the_first_test():
    """S-1: the session's set-up made a real daemon answer (started or found), and `docker`
    is the real CLI, not the stand-in."""
    assert conftest.REAL_DOCKER_ERROR is None
    first = conftest.REAL_DOCKER_LINES[0]
    assert first.startswith(("started dockerd", "using the Docker daemon already running")), first
    assert "FAKE_DOCKER_DIR" not in os.environ
    info = subprocess.run(["docker", "info", "--format", "{{.ID}} {{.Driver}}"],
                          capture_output=True, text=True, check=True).stdout.split()
    assert len(info) == 2 and info[0], info
    again = realdocker.ensure_daemon()
    assert again.startswith("using the Docker daemon already running")


@pytest.mark.real_docker
def test_the_real_daemon_takes_the_mirror_copy_when_docker_hub_is_refused(monkeypatch):
    """S-3 on the real daemon: drop the pinned PostgREST tag (a spare tag keeps the layers, so
    nothing is downloaded again), refuse Docker Hub, and the helper puts it back from
    mirror.gcr.io under the pinned name."""
    spare = "rlsentry-test-spare/postgrest:v12.2.3"
    subprocess.run(["docker", "tag", REST_IMAGE, spare], check=True, capture_output=True)
    before = realdocker._image_id(REST_IMAGE)
    try:
        subprocess.run(["docker", "rmi", REST_IMAGE], check=True, capture_output=True)
        assert realdocker._image_id(REST_IMAGE) is None
        monkeypatch.setenv("RLSENTRY_TEST_REFUSE_REGISTRY", "docker.io")

        said = realdocker.ensure_image(REST_IMAGE)

        assert said.startswith(f"{REST_IMAGE}: pulled from mirror.gcr.io"), said
        assert realdocker._image_id(REST_IMAGE) == before
    finally:
        if realdocker._image_id(REST_IMAGE) is None:
            subprocess.run(["docker", "tag", spare, REST_IMAGE], capture_output=True)
        subprocess.run(["docker", "rmi", spare], capture_output=True)
