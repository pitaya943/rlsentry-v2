-- Supabase's starter: a profile made for each new user by a trigger on auth.users,
-- reading the columns such triggers typically read.
create table public.profiles (
  id uuid not null references auth.users on delete cascade primary key,
  email text,
  full_name text,
  provider text,
  phone text,
  joined_at timestamptz,
  confirmed_at timestamptz,
  last_seen_at timestamptz,
  anonymous boolean
);
alter table public.profiles enable row level security;
create policy "Public profiles are viewable by everyone." on public.profiles
  for select using (true);

create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, email, full_name, provider, phone, joined_at, confirmed_at,
                               last_seen_at, anonymous)
  values (new.id, new.email, new.raw_user_meta_data ->> 'full_name',
          new.raw_app_meta_data ->> 'provider', new.phone, new.created_at,
          coalesce(new.email_confirmed_at, new.confirmed_at), new.last_sign_in_at,
          new.is_anonymous);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute procedure public.handle_new_user();
