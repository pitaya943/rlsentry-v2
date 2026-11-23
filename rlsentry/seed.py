"""Fake rows for the copy, generated from column types. Runs as superuser, never as anon."""

from __future__ import annotations

import uuid

import psycopg

ROWS_PER_TABLE = 5

_INT = {"smallint", "integer", "bigint"}
_FLOAT = {"real", "double precision"}


def _value(type_name: str, column: str, i: int) -> str | None:
    base = type_name.split("(")[0]
    if base in _INT:
        return str(i + 1)
    if base in _FLOAT or base == "numeric":
        return f"{i + 1}.5"
    if base in {"text", "character varying", "character", "citext"}:
        return f"{column}-{i + 1}"[: _length(type_name)]
    if base == "boolean":
        return "true" if i % 2 == 0 else "false"
    if base == "uuid":
        return str(uuid.uuid4())
    if base.startswith("timestamp") or base == "date":
        return f"2026-01-{i + 1:02d} 12:00:00"
    if base in {"json", "jsonb"}:
        return f'{{"n": {i + 1}}}'
    return None


def _length(type_name: str) -> int | None:
    if "(" in type_name:
        return int(type_name.split("(")[1].rstrip(")").split(",")[0])
    return None


def _writable_columns(conn, schema: str, table: str) -> list[tuple[str, str]]:
    """Columns a row must supply: no default, not generated, not identity. (name, type)."""
    return conn.execute(
        """
        select a.attname, format_type(a.atttypid, a.atttypmod)
        from pg_attribute a
        where a.attrelid = format('%%I.%%I', %s::text, %s::text)::regclass
          and a.attnum > 0 and not a.attisdropped
          and a.attgenerated = '' and a.attidentity = ''
          and not a.atthasdef
        order by a.attnum
        """,
        (schema, table),
    ).fetchall()


def fake_row(conn, schema: str, table: str, i: int = ROWS_PER_TABLE) -> dict[str, str] | None:
    """Fake values (as text) for the writable columns of row number i; None if a type has none.

    The default i is the row after the seeded ones, so it differs from every seeded row."""
    values = {name: _value(typ, name, i) for name, typ in _writable_columns(conn, schema, table)}
    return None if None in values.values() else values


def seed_table(conn, schema: str, table: str) -> tuple[int, list[str]]:
    """Insert up to ROWS_PER_TABLE fake rows. Returns (rows inserted, notes)."""
    cols = _writable_columns(conn, schema, table)
    unsupported = [f"{name} ({typ})" for name, typ in cols if _value(typ, name, 0) is None]
    if unsupported:
        return 0, [f"not seeded: no fake value for column(s) {', '.join(unsupported)}"]

    names = ", ".join(f'"{name}"' for name, _ in cols)
    placeholders = ", ".join(f"%s::{typ}" for _, typ in cols)
    sql = (f'insert into "{schema}"."{table}" ({names}) values ({placeholders})' if cols
           else f'insert into "{schema}"."{table}" default values')
    try:
        with conn.transaction():
            for i in range(ROWS_PER_TABLE):
                conn.execute(sql, [_value(typ, name, i) for name, typ in cols])
    except psycopg.Error as err:  # the generator could not satisfy the table's constraints
        return 0, [f"not seeded: {str(err).splitlines()[0]}"]
    return ROWS_PER_TABLE, [f"seeded {ROWS_PER_TABLE} rows"]
