-- The auth stand-in reads the request's JWT claims the way Supabase's functions do.
select set_config('request.jwt.claims',
  '{"sub": "6f1c2a7e-0d4b-4e1a-9a3c-2b5d8e7f9a01", "role": "authenticated", "email": "a@example.com"}',
  true);
do $$
begin
  assert auth.uid() = '6f1c2a7e-0d4b-4e1a-9a3c-2b5d8e7f9a01'::uuid, 'auth.uid() did not read sub';
  assert auth.role() = 'authenticated', 'auth.role() did not read role';
  assert auth.jwt() ->> 'email' = 'a@example.com', 'auth.jwt() did not return the claims';
end $$;
select set_config('request.jwt.claims', '', true);
do $$
begin
  assert auth.uid() is null, 'auth.uid() without claims should be null';
  assert auth.role() is null, 'auth.role() without claims should be null';
end $$;

create table notes (id bigint generated always as identity primary key, body text);
alter table notes enable row level security;
