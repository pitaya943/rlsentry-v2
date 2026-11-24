"""Break each T-03 property one edit at a time; run the suite isolated; record which tests fail.
Run from anywhere in a checkout, as root: python3 docs/tasks/anon-probe/evidence/T-03-mutants/mutants.py [N ...]"""
import re
import subprocess
import sys
from pathlib import Path

WT = Path(__file__).resolve().parents[5]  # the checkout this file is in
ISO = str(Path(__file__).resolve().with_name("iso.sh"))
SB, SD, CLI = "rlsentry/sandbox.py", "rlsentry/seed.py", "rlsentry/cli.py"

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
    ("pgcrypto in public, not in extensions", SB,
     "create extension pgcrypto with schema extensions;", "create extension pgcrypto;"),
    ("uuid-ossp in public, not in extensions", SB,
     'create extension "uuid-ossp" with schema extensions;', 'create extension "uuid-ossp";'),
    ("extensions not on the server's search path (seeding, migrations)", SB,
     '             "-c", f"search_path={SEARCH_PATH}",\n', ""),
    ("extensions not on PostgREST's search path", SB,
     """            'db-extra-search-path = "public, extensions"\\n'\n""", ""),
    ("no usage on schema extensions for anon", SB,
     "grant usage on schema extensions to anon, authenticated, service_role;\n", ""),
    ("auth.users has no email", SB, "  email varchar(255),\n", ""),
    ("auth.users has no raw_user_meta_data", SB, "  raw_user_meta_data jsonb default '{}',\n", ""),
    ("auth.users has no last_sign_in_at", SB, "  last_sign_in_at timestamptz,\n", ""),
    ("auth.users has no confirmed_at", SB,
     "  confirmed_at timestamptz generated always as (least(email_confirmed_at, phone_confirmed_at)) stored,\n", ""),
    ("all migrations in one transaction", SB,
     "        for path in files:\n            text = path.read_text()\n",
     "        for path in files[-1:]:\n            text = '\\n'.join(p.read_text() for p in files)\n"),
    ("no transaction per migration", SB,
     "                    with conn.transaction():\n                        for start, statement in _statements(text):\n                            conn.execute(statement)",
     "                    for start, statement in _statements(text):\n                        conn.execute(statement)"),
    ("error does not name the file", SB,
     'raise BuildError(f"migration {path.name} failed at line "',
     'raise BuildError(f"a migration failed at line "'),
    ("error does not name the line", SB,
     'f"{text.count(chr(10), 0, at) + 1}: {detail}") from None', 'f"?: {detail}") from None'),
    ("error does not name the missing object", SB,
     'f"{text.count(chr(10), 0, at) + 1}: {detail}") from None', 'f"{text.count(chr(10), 0, at) + 1}") from None'),
    ("error line is the statement's, not the error's", SB,
     "at = start + int(pos) - 1 if pos else start", "at = start"),
    ("split: dollar quoting ignored", SB, '        elif kind == "dollar":\n', '        elif False:\n'),
    ("split: quoted strings ignored", SB,
     r"""  | (?P<string>[eE]'(?:[^'\\]|\\.|'')*(?:'|\Z)|'(?:[^']|'')*(?:'|\Z)|"(?:[^"]|"")*(?:"|\Z))""",
     "  | (?P<string>(?!))"),
    ("split: E'' backslash escapes ignored", SB, r"""[eE]'(?:[^'\\]|\\.|'')*(?:'|\Z)|""", ""),
    ("split: -- comments not skipped", SB, r"(?P<comment>--[^\n]*)", "(?P<comment>(?!))"),
    ("split: block comments not nested", SB,
     'level += 1 if text.startswith("/*", nxt) else -1', "level -= 1"),
    ("split: BEGIN ATOMIC bodies not tracked", SB,
     "                    depth += 1\n", "                    pass\n"),
    ("split: parentheses ignored", SB, "            parens += 1\n", "            pass\n"),
    ("unexpected exception exits 1 (no catch-all)", CLI,
     "    except Exception as err:  # exit 1", "    except ZeroDivisionError as err:  # exit 1"),
    ("another table's CHECK looked up in this one", SD,
     "check = plan.checks.get(name) if isinstance", "check = plan.checks[name] if isinstance"),
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
    ("no CHECK retries", SD, "    while err is not None:\n        name = err.diag",
     "    while err is not None:\n        return None, str(err)\n        name = err.diag"),
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
