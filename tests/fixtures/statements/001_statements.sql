-- Semicolons that do not end a statement; comment ; here
/* a block comment ; /* nested ; */ still a comment ; */
create table public."semi;colon" (
  id bigint generated always as identity primary key,
  plain text default 'a;b' check (plain <> 'x;y'),
  escaped text default E'it\'s; fine'
);
create function public.semi_count(t text) returns int language plpgsql as $body$
begin
  return length(t) - length(replace(t, ';', ''));
end $body$;
create function public.semi_twice(t text) returns int language sql
begin atomic
  select case when t is null then 0 else public.semi_count(t) * 2 end;
end;
create view public.semi_view as select public.semi_twice(plain) as n from public."semi;colon";
comment on table public."semi;colon" is 'a table; with a semicolon';
comment on column public."semi;colon".escaped is E'it\'s; escaped';
-- On the view, not a table: PostgREST cannot write to a table with a DO ALSO rule.
create rule semi_rule as on update to public.semi_view do instead (notify semi_a; notify semi_b);
