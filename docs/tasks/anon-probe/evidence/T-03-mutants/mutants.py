"""Break each T-03 property one edit at a time; run the suite isolated; record which tests fail."""
import re
import subprocess
import sys
from pathlib import Path

WT = Path("/home/user/rlsentry-v2/.shilaycow/worktrees/T-03")
ISO = "/tmp/claude-0/-home-user-rlsentry-v2/b9e11f1f-7126-5042-9467-51de14c64123/scratchpad/iso.sh"
SB, SD = "rlsentry/sandbox.py", "rlsentry/seed.py"

MUTANTS = [
    ("auth.uid() ignores the claims", SB,
     "select (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')::uuid",
     "select null::uuid"),
    ("auth.role() constant 'anon'", SB,
     "select nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'\n",
     "select 'anon'::text\n"),
    ("auth.jwt() returns {}", SB,
     "select nullif(current_setting('request.jwt.claims', true), '')::jsonb\n$$;",
     "select '{}'::jsonb\n$$;"),
    ("no usage on schema auth for anon", SB,
     "grant usage on schema auth to anon, authenticated, service_role;", ""),
    ("no auth.users table", SB, "create table auth.users (", "create table auth.users_gone ("),
    ("no uuid-ossp", SB, 'create extension "uuid-ossp" with schema extensions;', ""),
    ("no pgcrypto", SB, "create extension pgcrypto with schema extensions;", ""),
    ("extensions not on the database search path", SB,
     'alter database postgres set search_path = "$user", public, extensions;', ""),
    ("all migrations in one transaction", SB,
     """        for path in files:
            with path.open("rb") as migration:""",
     """        import io
        whole = b"".join(p.read_bytes() + b"\\n" for p in files)
        for path in files[-1:]:
            with io.BytesIO(whole) as migration:"""),
    ("no transaction per migration", SB, '"--single-transaction", ', ""),
    ("error does not name the file", SB,
     'raise BuildError(f"migration {path.name} failed{where}: {detail}")',
     'raise BuildError(f"a migration failed{where}: {detail}")'),
    ("error does not name the line", SB, 'f" at line {m[1]}"', '""'),
    ("error does not name the missing object", SB,
     'raise BuildError(f"migration {path.name} failed{where}: {detail}")',
     'raise BuildError(f"migration {path.name} failed{where}")'),
    ("no teardown when the build fails", SB,
     """        except BaseException:
            self.teardown()
            raise""",
     """        except BaseException:
            raise"""),
    ("no stop for an unseeded table", SB, "        if empty:\n", "        if False:\n"),
    ("unseeded stop does not name the reason", SB,
     'empty = [f"{s}.{t}: {r.reason}"', 'empty = [f"{s}.{t}"'),
    ("seed in name order, not FK order", SD,
     """        order += (sorted(t for t in left if parents.get(t, set()) <= done)
                  or sorted(t for t in left if required.get(t, set()) <= done)
                  or sorted(left))""",
     """        order += sorted(left)"""),
    ("seed auth.users and referenced tables last", SD,
     "    return order\n", "    return [t for t in order if t in tables] + [t for t in order if t not in tables]\n"),
    ("referenced tables not seeded", SD, "            todo.extend(parents.get(t, ()))", "            pass"),
    ("cycle broken by name, not by the nullable key", SD,
     "                  or sorted(t for t in left if required.get(t, set()) <= done)\n", ""),
    ("FK values random, not from the parent", SD,
     "gen = (lambda i, pos=pos, keys=keys: keys[i % len(keys)][pos]) if keys else None",
     "gen = None"),
    ("FK column with a default left to the default", SD,
     """        if name in fk:
            gen, parent = fk[name]
        elif has_default:
            continue""",
     """        if has_default:
            continue
        elif name in fk:
            gen, parent = fk[name]"""),
    ("empty-parent reason not named", SD,
     'f" references {parent}, which has no rows" if parent else ""', '""'),
    ("enums not generated", SD, '    if typtype == "e":', '    if False:'),
    ("arrays not generated", SD, '    if typ.endswith("[]"):\n        elem', '    if typ.endswith("[]"):\n        return None\n        elem'),
    ("array elements not escaped", SD,
     """'{"%s"}' % elem(i).replace("\\\\", "\\\\\\\\").replace('"', '\\\\"')""",
     """'{"%s"}' % elem(i)"""),
    ("varchar length not honoured", SD, 'f"{column}-{i + 1}"[:length]', 'f"{column}-{i + 1}"'),
    ("nullable unsupported column blocks the table", SD, "        elif notnull:\n            missing", "        else:\n            missing"),
    ("no CHECK retries", SD, "    while err is not None:\n        if not isinstance",
     "    while err is not None:\n        return str(err)\n        if not isinstance"),
    ("CHECK retries stop at the first CHECK", SD,
     "                row = attempt  # this CHECK is satisfied; on to the next one, if any\n                break",
     "                if err is None:\n                    return ''\n                return 'x'"),
    ("CHECK number +1 not tried", SD, "str(v), str(v + 1), str(v - 1)", "str(v), str(v - 1)"),
    ("CHECK number -1 not tried", SD, "str(v), str(v + 1), str(v - 1)", "str(v), str(v + 1)"),
    ("CHECK decimals not parsed", SD, 'v = float(n) if "." in n else int(n)', "v = int(n)"),
    ("CHECK string constants not unescaped", SD, """s.replace("''", "'") for s in""", "s for s in"),
    ("CHECK string constants not tried", SD, "                               else check.strings)", "                               else [])"),
    ("emptiness from rows inserted, not rows present", SD,
     "    return Seeded(rows, note, reason)", "    return Seeded(inserted, note, reason)"),
    ("partial seeding not noted", SD,
     """f"seeded {inserted} of {ROWS_PER_TABLE} rows; skipped: {reason}")""",
     """f"seeded {inserted} rows")"""),
    ("identifiers in f-strings", SD,
     """    rel = sql.Identifier(schema, table)""",
     """    rel = sql.SQL(f'"{schema}"."{table}"')"""),
    ("column identifiers in f-strings", SD,
     "rel, sql.SQL(\", \").join(map(sql.Identifier, names)),",
     "rel, sql.SQL(\", \").join(sql.SQL(f'\"{n}\"') for n in names),"),
    ("insert attack's row ignores CHECKs", SD, "    if not plan.checks:\n", "    if True:\n"),
    ("fake_row from column types only (no enum/FK/array)", SD,
     "    plan = _plan(conn, schema, table)\n    if plan.missing:\n        return None\n    if not",
     "    plan = _plan(conn, schema, table)\n    if plan.missing or any(n in plan.row(0) for n in ('role', 'user_id', 'tags', 'todo_id')):\n        return None\n    if not"),
]


def main(only=None):
    for i, (desc, rel, old, new) in enumerate(MUTANTS, 1):
        if only and i not in only:
            continue
        path = WT / rel
        src = path.read_text()
        assert src.count(old) == 1, f"M{i} {desc}: pattern found {src.count(old)} times"
        try:
            path.write_text(src.replace(old, new))
            run = subprocess.run([ISO, "python3", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                                  "-rfE"],
                                 capture_output=True, text=True, timeout=900)
            failed = [l.split(" ")[1] for l in run.stdout.splitlines() if l.startswith("FAILED")]
            counts = [l for l in run.stdout.splitlines() if re.search(r"\d+ (passed|failed|error)", l)]
            summary = counts[-1].strip("= ") if counts else run.stderr[-200:]
            if not failed:
                summary = "SURVIVED: " + summary
            print(f"M{i:02d} {desc}\n     {summary}")
            for f in failed[:3]:
                print(f"       {f}")
            sys.stdout.flush()
        finally:
            path.write_text(src)


if __name__ == "__main__":
    main({int(a) for a in sys.argv[1:]} or None)
