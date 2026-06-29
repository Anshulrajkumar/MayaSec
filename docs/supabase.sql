create table if not exists public.mayasec_users (
  user_id uuid primary key,
  email text not null,
  api_key text not null unique,
  allowed_domains jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint mayasec_users_allowed_domains_is_array
    check (jsonb_typeof(allowed_domains) = 'array')
);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists mayasec_users_set_updated_at on public.mayasec_users;

create trigger mayasec_users_set_updated_at
before update on public.mayasec_users
for each row
execute function public.set_updated_at();
