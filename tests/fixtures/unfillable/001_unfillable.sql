-- A column type rlsentry has no fake value for: the table can be neither seeded nor attacked.
create table tagged (
  id bigint generated always as identity primary key,
  here point not null
);
