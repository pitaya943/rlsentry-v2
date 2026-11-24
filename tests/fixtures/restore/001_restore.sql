-- One wide-open table whose email is unique. If the row the insert attack created were
-- left behind, the update attack (which sets row 1's email to that same fresh value) would
-- fail with a unique violation and look protected. It is also the last table, so the
-- delete attack is the run's last write.
create table uniq_email (
  id bigint generated always as identity primary key,
  email text not null unique
);
