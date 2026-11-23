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
