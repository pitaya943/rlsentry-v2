-- A column type rlsentry has no fake value for: the table cannot be attacked for writes.
create table tagged (
  id bigint generated always as identity primary key,
  tags text[] not null
);
