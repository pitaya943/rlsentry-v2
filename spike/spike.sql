\set VERBOSITY verbose
\set ON_ERROR_STOP 0
create role anon nologin;
create extension if not exists pgcrypto;
-- 1 RLS off, granted
create table t_open (id uuid primary key default gen_random_uuid(), v text);
-- 2 RLS on, with check (true)
create table t_true (id uuid primary key default gen_random_uuid(), v text);
alter table t_true enable row level security;
create policy p on t_true for insert to anon with check (true);
-- 3 RLS on, restrictive check
create table t_owner (id uuid primary key default gen_random_uuid(), owner text);
alter table t_owner enable row level security;
create policy p on t_owner for insert to anon with check (owner = 'never');
-- 4 RLS on, no policy
create table t_nopol (id uuid primary key default gen_random_uuid(), v text);
alter table t_nopol enable row level security;
-- 5 no grant
create table t_nogrant (id uuid primary key default gen_random_uuid(), v text);
-- 6 identity always
create table t_ident (id bigint generated always as identity primary key, v text);
-- 7 before trigger fills id
create table t_trig (id uuid primary key, v text);
create function fill() returns trigger language plpgsql as $$ begin new.id := coalesce(new.id, gen_random_uuid()); return new; end $$;
create trigger tg before insert on t_trig for each row execute function fill();
-- 8 with check depends on a column we leave null (policy evaluated on the null row)
create table t_coldep (id uuid primary key default gen_random_uuid(), owner text);
alter table t_coldep enable row level security;
create policy p on t_coldep for insert to anon with check (owner is null or owner = 'x');
grant insert, select on t_open, t_true, t_owner, t_nopol, t_ident, t_trig, t_coldep to anon;
set role anon;
\echo === 1 t_open (expect 23502 = exposed)
insert into t_open (id) values (null);
\echo === 2 t_true (expect 23502 = exposed)
insert into t_true (id) values (null);
\echo === 3 t_owner (expect 42501 = protected)
insert into t_owner (id) values (null);
\echo === 4 t_nopol (expect 42501)
insert into t_nopol (id) values (null);
\echo === 5 t_nogrant (expect 42501 permission denied)
insert into t_nogrant (id) values (null);
\echo === 6 t_ident
insert into t_ident (id) values (null);
\echo === 7 t_trig (DANGER: row may persist)
insert into t_trig (id) values (null);
\echo === 8 t_coldep
insert into t_coldep (id) values (null);
\echo === 9 multi-row insert where second row ok: does anything persist
insert into t_open (id) values (gen_random_uuid()), (null);
reset role;
\echo === row counts after
select 't_open', count(*) from t_open union all select 't_true',count(*) from t_true union all select 't_trig',count(*) from t_trig;
