create table public.files (
  id bigint generated always as identity primary key,
  name text not null,
  bucket_id storage.bucket_kind
);
