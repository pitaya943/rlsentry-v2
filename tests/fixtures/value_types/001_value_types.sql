-- Policies and CHECKs whose constants the column cannot hold, and an insert policy for
-- another role. Anon can satisfy none of these tables' insert policies: each must read
-- "protected (N rows tried)", never stop the run over a candidate the column cannot take.

-- (verdict D1) an interval in the policy's term about a timestamptz
create table posts (
  id bigint generated always as identity primary key,
  user_id uuid,
  created_at timestamptz not null default now()
);
alter table posts enable row level security;
create policy "own recent posts" on posts for insert to anon
  with check (created_at > now() - interval '1 day' and auth.uid() = user_id);

-- (verdict D1) an interval in a CHECK on dates
create table bookings (
  id bigint generated always as identity primary key,
  owner uuid not null,
  starts_at date not null,
  ends_at date not null check (ends_at < starts_at + interval '30 days')
);
alter table bookings enable row level security;
create policy p on bookings for insert to anon with check (auth.uid() = owner);

-- (verdict D1) a decimal bound on an integer: 0.5, 1.5 and -0.5 are no integers
create table t_int (
  id bigint generated always as identity primary key,
  owner uuid not null,
  n int not null check (n > 0.5)
);
alter table t_int enable row level security;
create policy p on t_int for insert to anon with check (auth.uid() = owner);

-- the top of smallint's range: 32768 is no smallint
create table t_small (
  id bigint generated always as identity primary key,
  owner uuid not null,
  s smallint not null check (s <= 32767)
);
alter table t_small enable row level security;
create policy p on t_small for insert to anon with check (auth.uid() = owner);

-- 'role' is a string the policy reads a claim by, not the role column
create table t_role (
  id bigint generated always as identity primary key,
  owner uuid not null,
  role text not null
);
alter table t_role enable row level security;
create policy p on t_role for insert to anon
  with check (auth.jwt() ->> 'role' = 'admin' and auth.uid() = owner);

-- 'abcd' casts to varchar(3) (truncated) but PostgREST refuses it as too long (22001):
-- a candidate the column cannot hold, not an answer about the policy
create table t_len (
  id bigint generated always as identity primary key,
  owner uuid not null,
  code varchar(3) not null check (code <> 'abcd')
);
alter table t_len enable row level security;
create policy p on t_len for insert to anon with check (auth.uid() = owner);

-- an insert policy for authenticated users only: its constant is no candidate for anon
create table t_auth (
  id bigint generated always as identity primary key,
  owner uuid not null,
  kind text not null
);
alter table t_auth enable row level security;
create policy p on t_auth for insert to anon with check (auth.uid() = owner);
create policy staff on t_auth for insert to authenticated with check (kind = 'staff');
