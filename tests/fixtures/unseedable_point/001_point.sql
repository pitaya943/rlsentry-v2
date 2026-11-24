create table spots (id bigint generated always as identity primary key, here point not null);
create table spot_visits (id bigint generated always as identity primary key,
                          spot_id bigint not null references spots);
