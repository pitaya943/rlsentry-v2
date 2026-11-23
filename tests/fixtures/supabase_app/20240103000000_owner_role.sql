-- A later migration grows the enum; the next one relies on the new value being committed.
alter type public.user_role add value 'owner';
