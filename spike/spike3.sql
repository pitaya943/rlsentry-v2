\set VERBOSITY terse
create table u_open (id uuid primary key default gen_random_uuid(), v text);
create table u_rlsck (id uuid primary key default gen_random_uuid(), owner text);
alter table u_rlsck enable row level security;
create policy s on u_rlsck for select to anon using (true);
create policy u on u_rlsck for update to anon using (true) with check (owner = 'never');
create table u_noupd (id uuid primary key default gen_random_uuid(), v text);
alter table u_noupd enable row level security;
create policy s on u_noupd for select to anon using (true);
insert into u_open default values; insert into u_rlsck default values; insert into u_noupd default values;
grant select, update on u_open, u_rlsck, u_noupd to anon;
set role anon;
\echo === U1 u_open set id=null (expect 23502)
update u_open set id = null where id = (select id from u_open limit 1);
\echo === U2 u_rlsck update with-check rejects (expect 42501)
update u_rlsck set id = null where id = (select id from u_rlsck limit 1);
\echo === U3 u_noupd no update policy (expect UPDATE 0)
update u_noupd set id = null where id = (select id from u_noupd limit 1);
