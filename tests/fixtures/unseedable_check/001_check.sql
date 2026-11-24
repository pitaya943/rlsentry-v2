create table impossible (
  id bigint generated always as identity primary key,
  code text not null check (code = reverse(code) and length(code) > 40)
);
