create type kind as enum ();
create table things (id bigint generated always as identity primary key, kind kind not null);
