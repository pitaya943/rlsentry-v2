-- uuid-ossp and pgcrypto come installed in schema extensions, on the search path.
create table public.todos (
  id uuid default uuid_generate_v4() primary key,
  user_id uuid not null default auth.uid() references public.profiles,
  task text check (char_length(task) > 3),
  priority int not null check (priority between 1 and 3),
  share_token text default encode(gen_random_bytes(12), 'hex'),
  is_complete boolean default false,
  inserted_at timestamp with time zone default timezone('utc'::text, now()) not null
);

alter table public.todos enable row level security;

create policy "Individuals can create todos." on public.todos
  for insert with check ((select auth.uid()) = user_id);
create policy "Individuals can view their own todos." on public.todos
  for select using ((select auth.uid()) = user_id);
create policy "Individuals can update their own todos." on public.todos
  for update using ((select auth.uid()) = user_id);
create policy "Individuals can delete their own todos." on public.todos
  for delete using ((select auth.uid()) = user_id);
