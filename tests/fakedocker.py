"""A stand-in for the docker CLI and daemon, for the docker backend's tests (no daemon here).

Containers are local processes: `postgres:16` runs this machine's PostgreSQL 16 and
`postgrest/postgrest:v12.2.3` this machine's PostgREST, each listening where `-p` publishes
the container's port (PostgREST through `--network container:<db>`, as the real one shares the
database container's network namespace). Any other image runs `sleep`. State lives in
$FAKE_DOCKER_DIR: state.json (images, containers) and calls.jsonl (every argv, in order).

$FAKE_DOCKER_FAIL, a comma-separated list, breaks the daemon on purpose:
  daemon        no daemon answers (every command fails)
  pull          pulls fail (Docker Hub's 429); no image is present beforehand
  remote        the current context's endpoint is a TCP host on another machine
  db-exits      the postgres container exits as soon as it starts
  rest-run      `docker run` of PostgREST fails after creating the container
  wide-publish  ports are published on every interface, whatever `-p` asks
"""

import fcntl
import glob
import json
import os
import pwd
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

D = Path(os.environ["FAKE_DOCKER_DIR"])
FAIL = set(filter(None, os.environ.get("FAKE_DOCKER_FAIL", "").split(",")))
PG_BIN = sorted(glob.glob("/usr/lib/postgresql/*/bin"))[-1]


class Exit(Exception):
    def __init__(self, code, message=""):
        self.code, self.message = code, message


def alive(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def running(c):
    return c["status"] == "running" and c["pids"] and all(alive(p) for p in c["pids"])


def load():
    path = D / "state.json"
    return json.loads(path.read_text()) if path.exists() else {"images": [], "containers": {}}


def find(state, ref):
    for name, c in state["containers"].items():
        if ref in (name, c["id"]):
            return name
    return None


def remove(state, name):
    c = state["containers"].pop(name)
    for pid in c["pids"]:
        if alive(pid):
            os.kill(pid, signal.SIGINT if c["image"] == "postgres:16" else signal.SIGTERM)
            deadline = time.monotonic() + 15
            while alive(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            if alive(pid):
                os.kill(pid, signal.SIGKILL)
    shutil.rmtree(c["dir"], ignore_errors=True)


def prune(state):
    """`--rm`: a container whose process has exited is removed by the daemon."""
    for name, c in list(state["containers"].items()):
        if c["rm"] and c["status"] == "running" and not running(c):
            remove(state, name)


def spawn(c, argv, user=None):
    log = open(Path(c["dir"]) / "log", "ab")
    kw = {}
    if user is not None:
        kw = dict(user=user.pw_uid, group=user.pw_gid, extra_groups=[])
    env = {k: v for k, v in os.environ.items() if not k.startswith("PGRST_")}  # PostgREST reads these too
    proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                            cwd=c["dir"], env=env, **kw)
    c["pids"].append(proc.pid)


def published(c, port):
    for ip, host, cport in c["ports"]:
        if cport == port:
            return ip, host
    return None


def run(state, args):
    opts = {"rm": False, "name": None, "labels": {}, "ports": [], "env": {}, "network": None}
    while args and args[0].startswith("-"):
        flag = args.pop(0)
        if flag == "-d":
            continue
        if flag == "--rm":
            opts["rm"] = True
            continue
        if flag not in ("--name", "--label", "-p", "-e", "--network"):
            raise Exit(125, f"fake docker: unsupported flag {flag}")
        value = args.pop(0)
        if flag == "--name":
            opts["name"] = value
        elif flag == "--label":
            k, _, v = value.partition("=")
            opts["labels"][k] = v
        elif flag == "-p":
            parts = value.split(":")
            ip, host, cport = (parts if len(parts) == 3 else ["", *parts])
            opts["ports"].append(["" if "wide-publish" in FAIL else ip, int(host), int(cport)])
        elif flag == "-e":
            k, eq, v = value.partition("=")
            if eq:
                opts["env"][k] = v
            elif k in os.environ:
                opts["env"][k] = os.environ[k]
        elif flag == "--network":
            opts["network"] = value
    image, command = args[0], args[1:]
    if image not in state["images"]:
        if "pull" in FAIL:
            raise Exit(125, "docker: Error response from daemon: toomanyrequests: You have reached your pull rate limit.")
        state["images"].append(image)
    name = opts["name"] or "c" + secrets.token_hex(4)
    if name in state["containers"]:
        raise Exit(125, f'docker: Error response from daemon: Conflict. The container name "/{name}" is already in use.')
    if opts["ports"] and opts["network"]:
        raise Exit(125, "docker: conflicting options: port publishing and the container type network mode.")
    cid = secrets.token_hex(6)
    c = {"id": cid, "name": name, "image": image, "labels": opts["labels"], "ports": opts["ports"],
         "rm": opts["rm"], "pids": [], "status": "created",
         # Under /tmp: the pytest tmp dir is not reachable for the `postgres` user.
         "dir": tempfile.mkdtemp(prefix=f"fakedocker-{cid}-", dir="/tmp"),
         "env": sorted(opts["env"]), "internal": {}}
    state["containers"][name] = c
    user = pwd.getpwnam("postgres") if os.geteuid() == 0 else None
    if user:
        os.chown(c["dir"], user.pw_uid, user.pw_gid)

    if image == "postgres:16":
        trust = opts["env"].get("POSTGRES_HOST_AUTH_METHOD") == "trust"
        if "db-exits" in FAIL or not (trust or opts["env"].get("POSTGRES_PASSWORD")):
            spawn(c, ["sh", "-c", "echo 'Error: Database is uninitialized and superuser password is not specified.'; exit 1"])
        else:
            data = Path(c["dir"]) / "data"
            subprocess.run([f"{PG_BIN}/initdb", "-D", str(data), "-U", "postgres", "--auth=trust",
                            "--no-sync", "--no-instructions"], check=True, capture_output=True,
                           cwd=c["dir"], **({} if user is None else dict(user=user.pw_uid, group=user.pw_gid)))
            pub = published(c, 5432)
            port = pub[1] if pub else _free_port()
            c["internal"] = {"5432": port}
            listen = (pub[0] or "*") if pub else "127.0.0.1"
            if command and not command[0].startswith("-"):
                command = command[1:]  # "postgres -c ..." as well as "-c ..."
            spawn(c, [f"{PG_BIN}/postgres", "-D", str(data), "-p", str(port), "-c", f"listen_addresses={listen}",
                      "-c", "unix_socket_directories=", *command], user)
    elif image == "postgrest/postgrest:v12.2.3":
        if not (opts["network"] or "").startswith("container:"):
            raise Exit(125, "fake docker: PostgREST needs --network container:<db>")
        host = state["containers"].get(find(state, opts["network"].split(":", 1)[1]))
        if host is None or not running(host):
            raise Exit(125, "docker: Error response from daemon: cannot join network of a non running container")
        if "rest-run" in FAIL:
            raise Exit(125, "docker: Error response from daemon: driver failed programming external connectivity.")
        env = opts["env"]
        conf = {k[len("PGRST_"):].lower().replace("_", "-"): v for k, v in env.items() if k.startswith("PGRST_")}
        conf["db-uri"] = conf.get("db-uri", "").replace("@127.0.0.1:5432/", f"@127.0.0.1:{host['internal']['5432']}/")
        pub = published(host, int(conf.get("server-port", 3000)))
        conf["server-host"] = (pub[0] or "*4") if pub else "127.0.0.1"
        conf["server-port"] = str(pub[1] if pub else _free_port())
        path = Path(c["dir"]) / "postgrest.conf"
        path.write_text("".join(f'{k} = "{v}"\n' for k, v in conf.items() if k != "server-port")
                        + f"server-port = {conf['server-port']}\n")
        spawn(c, [shutil.which("postgrest"), str(path)])
    else:
        spawn(c, ["sleep", "3600"])
    c["status"] = "running"
    return cid


def _free_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def fmt(template, c):
    out = template.replace("{{.ID}}", c["id"]).replace("{{.Names}}", c["name"])
    out = out.replace("{{.State.Running}}", "true" if running(c) else "false")
    return re.sub(r'\{\{\.Label "([^"]+)"\}\}', lambda m: c["labels"].get(m[1], ""), out).replace("\\t", "\t")


def main(argv):
    with open(D / "calls.jsonl", "a") as log:
        log.write(json.dumps(argv) + "\n")
    if "daemon" in FAIL:
        raise Exit(1, "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?")
    cmd, args = argv[0], argv[1:]
    if cmd == "version":
        return "27.0.0-fake"
    if cmd == "context":
        return "tcp://10.20.30.40:2376" if "remote" in FAIL else "unix:///var/run/docker.sock"
    with open(D / "lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = load()
        prune(state)
        try:
            return dispatch(state, cmd, args)
        finally:
            (D / "state.json").write_text(json.dumps(state, indent=1))


def dispatch(state, cmd, args):
    if cmd == "image" and args[0] == "inspect":
        if args[1] not in state["images"]:
            raise Exit(1, f"Error: No such image: {args[1]}")
        return "[{}]"
    if cmd == "pull":
        if "pull" in FAIL:
            raise Exit(1, "Error response from daemon: toomanyrequests: You have reached your pull rate limit.")
        state["images"].append(args[0])
        return f"{args[0]}: Pulled"
    if cmd == "run":
        return run(state, list(args))
    if cmd == "ps":
        quiet, template, filters = False, "{{.ID}}\t{{.Names}}", []
        while args:
            flag = args.pop(0)
            if flag == "-q":
                quiet = True
            elif flag == "--filter":
                filters.append(args.pop(0))
            elif flag == "--format":
                template = args.pop(0)
            elif flag != "-a":
                raise Exit(125, f"fake docker: unsupported flag {flag}")
        lines = []
        for c in state["containers"].values():
            ok = True
            for f in filters:
                key, _, spec = f.partition("=")
                assert key == "label", f
                k, eq, v = spec.partition("=")
                ok &= k in c["labels"] and (not eq or c["labels"][k] == v)
            if ok:
                lines.append(c["id"] if quiet else fmt(template, c))
        return "\n".join(lines)
    if cmd == "inspect":
        template = args[1] if args[0] in ("-f", "--format") else None
        refs = args[2:] if template else args
        out, missing = [], []
        for ref in refs:
            name = find(state, ref)
            if name is None:
                missing.append(ref)
            else:
                out.append(fmt(template, state["containers"][name]) if template else json.dumps(state["containers"][name]))
        if missing:
            print("\n".join(out))
            raise Exit(1, "\n".join(f"Error: No such object: {m}" for m in missing))
        return "\n".join(out)
    if cmd == "port":
        c = state["containers"].get(find(state, args[0]))
        if c is None:
            raise Exit(1, f"Error: No such container: {args[0]}")
        ip_of = lambda ip: ip or "0.0.0.0"
        return "\n".join(f"{cport}/tcp -> {ip_of(ip)}:{host}" for ip, host, cport in c["ports"])
    if cmd == "logs":
        ref = args[-1]
        c = state["containers"].get(find(state, ref))
        if c is None:
            raise Exit(1, f"Error: No such container: {ref}")
        return (Path(c["dir"]) / "log").read_text(errors="replace")[-2000:]
    if cmd == "rm":
        refs = [a for a in args if not a.startswith("-")]
        missing = []
        for ref in refs:
            name = find(state, ref)
            if name is None:
                missing.append(ref)
            else:
                remove(state, name)
                print(ref)
        if missing:
            raise Exit(1, "\n".join(f"Error response from daemon: No such container: {m}" for m in missing))
        return None
    raise Exit(1, f"fake docker: unsupported command {cmd}")


if __name__ == "__main__":
    try:
        out = main(sys.argv[1:])
        if out:
            print(out)
    except Exit as e:
        if e.message:
            print(e.message, file=sys.stderr)
        sys.exit(e.code)
