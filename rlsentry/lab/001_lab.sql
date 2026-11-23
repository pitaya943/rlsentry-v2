-- rlsentry lab: each table is one deliberate mistake (or none). Expected verdicts: expected.json.

-- RLS never enabled: Supabase's default grants give anon everything.
create table lab_rls_off (
  id bigint generated always as identity primary key,
  email text not null,
  note text
);

-- RLS on, but the read policy lets everyone through.
create table lab_using_true (
  id bigint generated always as identity primary key,
  email text not null,
  note text
);
alter table lab_using_true enable row level security;
create policy "anyone can read" on lab_using_true for select to anon using (true);

-- RLS on and no policy at all: anon sees nothing.
create table lab_no_policy (
  id bigint generated always as identity primary key,
  email text not null,
  note text
);
alter table lab_no_policy enable row level security;

-- Anon may add rows, and only that: no read, update or delete policy.
create table lab_insert_only (
  id bigint generated always as identity primary key,
  email text not null,
  note text
);
alter table lab_insert_only enable row level security;
create policy "anyone can sign up" on lab_insert_only for insert to anon with check (true);

-- Anon may change any row. With no read policy it cannot pick a row by its id,
-- but a PATCH without a filter still rewrites every row.
create table lab_update_open (
  id bigint generated always as identity primary key,
  email text not null,
  note text
);
alter table lab_update_open enable row level security;
create policy "anyone can edit" on lab_update_open for update to anon using (true);

-- Anon may delete any row (again only without a filter, as there is no read policy).
create table lab_delete_open (
  id bigint generated always as identity primary key,
  email text not null,
  note text
);
alter table lab_delete_open enable row level security;
create policy "anyone can delete" on lab_delete_open for delete to anon using (true);

-- Done right: every policy checks the row's owner. Anon has no user id, so nothing passes.
create table lab_owner_only (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  note text
);
alter table lab_owner_only enable row level security;
create policy "owner reads" on lab_owner_only for select using (auth.uid() = user_id);
create policy "owner adds" on lab_owner_only for insert with check (auth.uid() = user_id);
create policy "owner edits" on lab_owner_only for update using (auth.uid() = user_id)
  with check (auth.uid() = user_id);
create policy "owner deletes" on lab_owner_only for delete using (auth.uid() = user_id);
