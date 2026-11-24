-- Written the way a Supabase starter app writes its first migration.
create type public.user_role as enum ('member', 'admin');

create table public.profiles (
  id uuid not null references auth.users on delete cascade,
  username text unique check (char_length(username) >= 3),
  role public.user_role not null,
  tier text not null check (tier in ('free', 'pro')),
  tags text[] not null,
  updated_at timestamp with time zone default now(),
  primary key (id)
);

alter table public.profiles enable row level security;

create policy "Public profiles are viewable by everyone." on public.profiles
  for select using (true);
create policy "Users can insert their own profile." on public.profiles
  for insert with check ((select auth.uid()) = id);
create policy "Users can update own profile." on public.profiles
  for update using ((select auth.uid()) = id);
