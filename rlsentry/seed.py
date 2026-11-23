"""Fake rows for the copy, generated from column types, enums, CHECK constraints and foreign
keys. Runs as superuser, never as anon. Every identifier goes through `psycopg.sql`."""

from __future__ import annotations

import itertools
import re
import uuid
from dataclasses import dataclass
from typing import Callable

import psycopg
from psycopg import sql

ROWS_PER_TABLE = 5
CHECK_TRIES_PER_ROW = 50

_INT = {"smallint", "integer", "bigint"}
_NUMERIC = _INT | {"real", "double precision", "numeric"}
_TEXT = {"text", "character varying", "character", "citext"}

Generator = Callable[[int], "str | None"]


@dataclass(frozen=True)
class Seeded:
    rows: int    # rows in the table afterwards, whoever put them there
    note: str
    reason: str  # why fake rows were skipped ("" if none were)


def seed(conn: psycopg.Connection, tables: list[tuple[str, str]]) -> dict[tuple[str, str], Seeded]:
    """Seed `tables` and every table they reference, each after the tables it points at."""
    return {t: _seed_table(conn, *t) for t in _fk_order(conn, tables)}


def _fk_order(conn, tables):
    parents: dict[tuple, set] = {}  # every table a table points at
    required: dict[tuple, set] = {}  # ... through a NOT NULL foreign key
    for cs, ct, rs, rt, notnull in conn.execute("""
        select cn.nspname, c.relname, rn.nspname, r.relname,
               (select bool_and(attnotnull) from pg_attribute
                where attrelid = k.conrelid and attnum = any(k.conkey))
        from pg_constraint k
        join pg_class c on c.oid = k.conrelid join pg_namespace cn on cn.oid = c.relnamespace
        join pg_class r on r.oid = k.confrelid join pg_namespace rn on rn.oid = r.relnamespace
        where k.contype = 'f'
    """):
        if (cs, ct) != (rs, rt):  # a self-reference cannot be ordered; it gets null or nothing
            parents.setdefault((cs, ct), set()).add((rs, rt))
            if notnull:
                required.setdefault((cs, ct), set()).add((rs, rt))
    wanted, todo = set(), list(tables)
    while todo:
        t = todo.pop()
        if t not in wanted:
            wanted.add(t)
            todo.extend(parents.get(t, ()))
    order: list = []
    while len(order) < len(wanted):
        left, done = wanted - set(order), set(order)
        # Parents first. In a cycle, a nullable key is left null to break it; a cycle of
        # NOT NULL keys cannot be seeded, and the constraints will say so.
        order += (sorted(t for t in left if parents.get(t, set()) <= done)
                  or sorted(t for t in left if required.get(t, set()) <= done)
                  or sorted(left))
    return order


def _seed_table(conn, schema: str, table: str) -> Seeded:
    rel = sql.Identifier(schema, table)
    oid = conn.execute("select %s::regclass::oid", (rel.as_string(conn),)).fetchone()[0]
    fk = _fk_generators(conn, oid)
    generators: dict[str, tuple[str, Generator]] = {}
    missing = []
    for name, typ, notnull, has_default, typoid, elemoid in conn.execute("""
        select a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull,
               a.atthasdef or a.attgenerated <> '' or a.attidentity <> '',
               a.atttypid, t.typelem
        from pg_attribute a join pg_type t on t.oid = a.atttypid
        where a.attrelid = %s and a.attnum > 0 and not a.attisdropped
        order by a.attnum
    """, (oid,)).fetchall():
        if name in fk:
            gen, parent = fk[name]
        elif has_default:
            continue
        else:
            gen, parent = _generator(conn, name, typ, typoid, elemoid), None
        if gen is not None:
            generators[name] = (typ, gen)
        elif notnull:
            missing.append(f"{name} ({typ})"
                           + (f" references {parent}, which has no rows" if parent else ""))

    inserted, reason = 0, ""
    if missing:
        reason = f"no fake value for column(s) {', '.join(missing)}"
    else:
        names = list(generators)
        insert = (sql.SQL("insert into {} ({}) values ({})").format(
                      rel, sql.SQL(", ").join(map(sql.Identifier, names)),
                      sql.SQL(", ").join(sql.SQL("%s::" + generators[n][0]) for n in names))
                  if names else sql.SQL("insert into {} default values").format(rel))
        checks = _checks(conn, oid)
        for i in range(ROWS_PER_TABLE):
            err = _insert(conn, insert, names, {n: g(i) for n, (_, g) in generators.items()},
                          checks, {n: t for n, (t, _) in generators.items()})
            if err:
                reason = err
            else:
                inserted += 1
    rows = conn.execute(sql.SQL("select count(*) from {}").format(rel)).fetchone()[0]
    note = (f"seeded {inserted} rows" if inserted == ROWS_PER_TABLE else
            f"seeded {inserted} of {ROWS_PER_TABLE} rows; skipped: {reason}")
    return Seeded(rows, note, reason)


def _generator(conn, column: str, typ: str, typoid: int, elemoid: int) -> Generator | None:
    if typ.endswith("[]"):
        elem = _generator(conn, column, "", elemoid, 0)
        if elem is None:
            return None
        return lambda i: '{"%s"}' % elem(i).replace("\\", "\\\\").replace('"', '\\"')
    typtype, base = conn.execute(
        "select typtype, format_type(oid, null) from pg_type where oid = %s", (typoid,)).fetchone()
    if typtype == "e":
        labels = [r[0] for r in conn.execute(
            "select enumlabel from pg_enum where enumtypid = %s order by enumsortorder", (typoid,))]
        return (lambda i: labels[i % len(labels)]) if labels else None
    if base in _INT:
        return lambda i: str(i + 1)
    if base in _NUMERIC:
        return lambda i: f"{i + 1}.5"
    if base in _TEXT:
        length = int(typ.split("(")[1].split(")")[0]) if "(" in typ else None
        return lambda i: f"{column}-{i + 1}"[:length]
    if base == "boolean":
        return lambda i: "true" if i % 2 == 0 else "false"
    if base == "uuid":
        return lambda i: str(uuid.uuid4())
    if base.startswith("timestamp") or base == "date":
        return lambda i: f"2026-01-{i + 1:02d} 12:00:00"
    if base in {"json", "jsonb"}:
        return lambda i: f'{{"n": {i + 1}}}'
    return None


def _fk_generators(conn, oid: int) -> dict[str, tuple[Generator | None, str]]:
    """Foreign-key columns take row i's key from the referenced table (seeded before this one)."""
    gens = {}
    for cols, refschema, reftable, refcols in conn.execute("""
        select array(select attname from unnest(k.conkey) with ordinality u(n, o)
                     join pg_attribute on attrelid = k.conrelid and attnum = u.n order by o),
               rn.nspname, r.relname,
               array(select attname from unnest(k.confkey) with ordinality u(n, o)
                     join pg_attribute on attrelid = k.confrelid and attnum = u.n order by o)
        from pg_constraint k join pg_class r on r.oid = k.confrelid
        join pg_namespace rn on rn.oid = r.relnamespace
        where k.conrelid = %s and k.contype = 'f'
    """, (oid,)).fetchall():
        keys = conn.execute(sql.SQL("select {} from {} order by {}").format(
            sql.SQL(", ").join(sql.SQL("{}::text").format(sql.Identifier(c)) for c in refcols),
            sql.Identifier(refschema, reftable),
            sql.SQL(", ").join(map(sql.Identifier, refcols)))).fetchall()
        for pos, col in enumerate(cols):
            gen = (lambda i, pos=pos, keys=keys: keys[i % len(keys)][pos]) if keys else None
            gens[col] = (gen, f"{refschema}.{reftable}")
    return gens


@dataclass(frozen=True)
class _Check:
    columns: list[str]
    strings: list[str]
    numbers: list[str]


def _checks(conn, oid: int) -> dict[str, _Check]:
    checks = {}
    for name, cols, definition in conn.execute("""
        select conname,
               array(select attname from unnest(conkey) u(n)
                     join pg_attribute on attrelid = conrelid and attnum = u.n),
               pg_get_constraintdef(oid)
        from pg_constraint where conrelid = %s and contype = 'c'
    """, (oid,)):
        strings = [s.replace("''", "'") for s in re.findall(r"'((?:[^']|'')*)'", definition)]
        numbers = []
        for n in re.findall(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])", definition):
            v = float(n) if "." in n else int(n)
            numbers += [str(v), str(v + 1), str(v - 1)]
        checks[name] = _Check(cols, strings, numbers)
    return checks


def _insert(conn, insert, names, row, checks, types) -> str:
    """Insert one row. While a CHECK rejects it, retry with the constants that CHECK mentions
    for its columns (at most CHECK_TRIES_PER_ROW tries in all). Returns "" on success, else
    why the row was skipped."""
    tries = 0
    err = _try(conn, insert, names, row)
    while err is not None:
        if not isinstance(err, psycopg.errors.CheckViolation):
            return str(err).splitlines()[0]
        name = err.diag.constraint_name
        check = checks[name]
        cols = [c for c in check.columns if c in row]
        options = [[row[c]] + (check.numbers if types[c].split("(")[0] in _NUMERIC
                               else check.strings) for c in cols]
        for combo in itertools.islice(itertools.product(*options), 1, None):
            if tries == CHECK_TRIES_PER_ROW:
                return f"no value tried satisfies check {name}"
            tries += 1
            attempt = dict(row, **dict(zip(cols, combo)))
            err = _try(conn, insert, names, attempt)
            if err is None or (isinstance(err, psycopg.errors.CheckViolation)
                               and err.diag.constraint_name != name):
                row = attempt  # this CHECK is satisfied; on to the next one, if any
                break
        else:
            return f"no value tried satisfies check {name}"
    return ""


def _try(conn, insert, names, values) -> psycopg.Error | None:
    try:
        with conn.transaction():
            conn.execute(insert, [values[n] for n in names])
    except psycopg.Error as err:
        return err
    return None
