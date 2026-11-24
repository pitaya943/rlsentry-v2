# Dumps PostgreSQL's log entries (plans and errors) for one anon GET per table of a migrations dir.
# Usage: PYTHONPATH=<checkout> python3 probe.py <dir with 001.sql>
import json, sys
from pathlib import Path
from rlsentry.sandbox import Sandbox
with Sandbox(Path(sys.argv[1]), "local") as sb:
    ch = sb.anon_channel()
    for t in sb.tables:
        r = ch.request("GET", t, {"select": "*"})
        print("==", t, r.status, json.dumps(r.body)[:100])
        for e in sb._log.request(r.request_id):
            m = e.get("message") or ""
            if e.get("func_name") == "explain_ExecutorEnd":
                p = json.loads(m.partition("plan:\n")[2])
                if "set_config" in p.get("Query Text",""): continue
                print(json.dumps(p, indent=1)[:2500])
            elif e.get("error_severity") == "ERROR":
                print("ERR", e.get("func_name"), e.get("state_code"), m, e.get("context"))
