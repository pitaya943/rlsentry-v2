-- Identifiers that break naive quoting, and tables the generator can only partly fill.
create table "q""uote" (
  "id" bigint generated always as identity primary key,
  "it's" varchar(4) not null,
  "Mixed Case" text not null check ("Mixed Case" in ('it''s', 'b')),
  "lab""el\s" text[] not null,
  spot point
);
create table "child "" table" (
  id bigint generated always as identity primary key,
  "parent""id" bigint not null references "q""uote",
  reply_to bigint references "child "" table"
);
-- Sorts before its parent, which references itself.
create table "a grandchild" (
  id bigint generated always as identity primary key,
  child_id bigint not null references "child "" table"
);
-- Only two values fit: two fake rows, the rest skipped.
create table pairs (side text unique not null check (side in ('left', 'right')));
-- A one-row settings table the migration fills itself: no fake row fits, it still has a row.
create table settings (id int primary key check (id = 1), value text);
insert into settings values (1, 'x');
