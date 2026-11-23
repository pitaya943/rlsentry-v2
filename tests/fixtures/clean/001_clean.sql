-- A table done right for anon: RLS on, no policy that lets anon in.
create table profiles (
  id bigint generated always as identity primary key,
  email text not null
);
alter table profiles enable row level security;
