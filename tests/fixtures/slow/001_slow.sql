-- Every row anon reads costs 30 s, so a run sits in its attack with both servers up.
create table slow (id bigint generated always as identity primary key, note text);
alter table slow enable row level security;
create policy "slow read" on slow for select to anon using ((select true from pg_sleep(30)));
