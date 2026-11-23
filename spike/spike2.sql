\set VERBOSITY terse
delete from t_trig;
-- trigger that ALWAYS overwrites id (worst case)
create table t_trig2 (id uuid primary key, v text);
create function fill2() returns trigger language plpgsql as $$ begin new.id := gen_random_uuid(); return new; end $$;
create trigger tg before insert on t_trig2 for each row execute function fill2();
-- insert allowed, select NOT allowed (no select policy)
create table t_noselect (id uuid primary key default gen_random_uuid(), v text);
alter table t_noselect enable row level security;
create policy p on t_noselect for insert to anon with check (true);
grant insert, select on t_trig2, t_noselect to anon;
set role anon;
\echo === A t_trig: two rows same explicit id (duplicate guard)
insert into t_trig (id) values ('00000000-0000-0000-0000-000000000001'),('00000000-0000-0000-0000-000000000001');
\echo === B t_trig2: null + duplicate (trigger overwrites everything)
insert into t_trig2 (id) values ('00000000-0000-0000-0000-000000000001'),('00000000-0000-0000-0000-000000000001');
\echo === C t_noselect: RETURNING without select policy
insert into t_noselect (v) values ('x') returning id;
\echo === D t_noselect: no RETURNING
insert into t_noselect (id) values (null);
\echo === E t_owner (restrictive, value-based) with a value that passes
insert into t_owner (id, owner) values (null, 'never');
reset role;
select 't_trig',count(*) from t_trig union all select 't_trig2',count(*) from t_trig2 union all select 't_noselect',count(*) from t_noselect;
