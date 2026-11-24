-- A trigger on auth.users inserts into another table whose CHECK the new row breaks.
create table public.profiles (
  id uuid primary key references auth.users,
  username text not null check (char_length(username) >= 3)
);
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, username)
  values (new.id, coalesce(new.raw_user_meta_data ->> 'username', ''));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute procedure public.handle_new_user();
