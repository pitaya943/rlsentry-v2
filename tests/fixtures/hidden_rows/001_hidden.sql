-- Anon can read every row, and has update and delete policies that match none of them.
-- PostgREST answers those requests 2xx with 0 rows; only a superuser check tells
-- "denied" from "done".
create table update_hidden (
  id bigint generated always as identity primary key,
  note text
);
alter table update_hidden enable row level security;
create policy "anyone can read" on update_hidden for select to anon using (true);
create policy "nobody's rows" on update_hidden for update to anon using (false);

create table delete_hidden (
  id bigint generated always as identity primary key,
  note text
);
alter table delete_hidden enable row level security;
create policy "anyone can read" on delete_hidden for select to anon using (true);
create policy "nobody's rows" on delete_hidden for delete to anon using (false);
