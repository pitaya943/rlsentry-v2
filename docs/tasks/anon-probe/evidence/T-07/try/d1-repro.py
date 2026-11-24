"""The PR #10 verdict's D1 reproductions, as the verifier ran them, with `rlsentry` from PATH:
a listener on 127.0.0.1:18777 answering every GET, and a policy that makes PostgREST answer 302
to it. Prints each run's output, exit code and what reached the listener."""
import http.server
import subprocess
import tempfile
import threading
from pathlib import Path

MIGRATION = """create table notes (id bigint generated always as identity primary key, body text not null);
alter table notes enable row level security;
create function public.bounce() returns boolean language plpgsql as $$
begin
  perform set_config('response.status', '302', true);
  perform set_config('response.headers', '[{"Location": "http://127.0.0.1:18777/rest/v1/elsewhere"}]', true);
  return RETURNS;
end $$;
create policy "no one reads" on notes for select to anon using (public.bounce());
"""

seen = []


class Listener(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        seen.append(f"{self.command} {self.path} auth={self.headers.get('Authorization', '')[:20]}...")
        body = self.server.body
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


for returns, body in (("false", b'[{"id":1,"secret":"FABRICATED-NOT-IN-COPY"}]'), ("true", b"[]")):
    server = http.server.HTTPServer(("127.0.0.1", 18777), Listener)
    server.body = body
    threading.Thread(target=server.serve_forever, daemon=True).start()
    seen.clear()
    with tempfile.TemporaryDirectory() as d:
        Path(d, "001_notes.sql").write_text(MIGRATION.replace("RETURNS", returns))
        print(f"$ rlsentry attack --backend local --migrations <dir>   # bounce() returns {returns},"
              f" listener answers {body.decode()}")
        run = subprocess.run(["rlsentry", "attack", "--backend", "local", "--migrations", d],
                             capture_output=True, text=True, timeout=120)
    print(run.stdout + run.stderr + f"[exit {run.returncode}]")
    print(f"listener log: {seen or 'nothing'}\n")
    server.shutdown()
    server.server_close()
