-- Written the way `supabase db diff` writes it: extension functions with their schema.
create table public.api_keys (
  id uuid not null default extensions.uuid_generate_v4() primary key,
  secret text not null default encode(extensions.gen_random_bytes(8), 'hex'),
  label text not null
);
alter table public.api_keys enable row level security;
