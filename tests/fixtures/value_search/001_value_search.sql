-- Insert policies that accept only some rows; the fresh fake row is refused by each, and value
-- search has to find a row each one accepts, from a different source each time.
create type public.grade as enum ('a', 'b', 'c', 'd', 'e');  -- fake row 6 gets 'a'

-- policy constants, two columns at once
create table vs_two (
  id bigint generated always as identity primary key,
  status text not null,
  kind text not null
);
alter table vs_two enable row level security;
create policy p on vs_two for insert to anon with check (status = 'pending' and kind = 'invite');

-- a number in the policy, met only by the number after it
create table vs_number (
  id bigint generated always as identity primary key,
  score int not null
);
alter table vs_number enable row level security;
create policy p on vs_number for insert to anon with check (score > 10);

-- enum labels
create table vs_enum (
  id bigint generated always as identity primary key,
  grade public.grade not null
);
alter table vs_enum enable row level security;
create policy p on vs_enum for insert to anon with check (grade <> 'a');

-- values in the seeded rows
create table vs_seeded (
  id bigint generated always as identity primary key,
  team text not null
);
alter table vs_seeded enable row level security;
create policy p on vs_seeded for insert to anon with check (team <> 'team-6');

-- null
create table vs_null (
  id bigint generated always as identity primary key,
  note text
);
alter table vs_null enable row level security;
create policy p on vs_null for insert to anon with check (note is null);
-- a constant in another command's policy is no candidate for an insert
create policy r on vs_null for select to anon using (note = 'visible');

-- nothing anon can send passes, and there are more candidates than the bound
create type public.many as enum ('m01', 'm02', 'm03', 'm04', 'm05', 'm06', 'm07', 'm08', 'm09',
  'm10', 'm11', 'm12', 'm13', 'm14', 'm15', 'm16', 'm17', 'm18', 'm19', 'm20', 'm21', 'm22',
  'm23', 'm24', 'm25', 'm26', 'm27', 'm28', 'm29', 'm30', 'm31', 'm32', 'm33', 'm34', 'm35',
  'm36', 'm37', 'm38', 'm39', 'm40', 'm41', 'm42', 'm43', 'm44', 'm45', 'm46', 'm47', 'm48',
  'm49', 'm50', 'm51', 'm52', 'm53', 'm54', 'm55', 'm56', 'm57', 'm58', 'm59', 'm60');
create table vs_owner (
  id bigint generated always as identity primary key,
  user_id uuid not null,
  label public.many not null
);
alter table vs_owner enable row level security;
create policy p on vs_owner for insert to anon with check (auth.uid() = user_id);
