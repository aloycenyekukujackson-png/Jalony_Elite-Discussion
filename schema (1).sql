-- JALONY_ELITE DISCUSSION: database ya kumbukumbu (Supabase / Postgres)
-- Endesha kwenye Supabase: Project > SQL Editor > New query > Run

-- 1. Wasifu wa wanafunzi (profile moja kwa kila akaunti)
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  email text not null unique,
  mobile text not null,
  reg_no text not null unique,
  created_at timestamptz default now()
);
alter table public.profiles enable row level security;
drop policy if exists "own profile read" on public.profiles;
create policy "own profile read" on public.profiles for select to authenticated using (auth.uid() = id);
drop policy if exists "own profile update" on public.profiles;
create policy "own profile update" on public.profiles for update to authenticated using (auth.uid() = id);

-- 2. Profile inaundwa kiotomatiki mtu anapojisajili
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name, email, mobile, reg_no)
  values (new.id,
          new.raw_user_meta_data->>'name',
          new.email,
          new.raw_user_meta_data->>'mobile',
          upper(new.raw_user_meta_data->>'reg_no'));
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 3. Orodha ya wanafunzi wote wa Tanzania: jina na reg no tu (simu haionekani)
create or replace view public.public_students as select name, reg_no from public.profiles;
grant select on public.public_students to authenticated;

-- 4. Kuingia kwa namba ya usajili (anon anaweza kupata barua pepe ya reg no tu)
create or replace function public.email_for_reg(p_reg text) returns text
language sql security definer set search_path = public as $$
  select email from public.profiles where reg_no = upper(p_reg) limit 1
$$;
grant execute on function public.email_for_reg(text) to anon, authenticated;

-- 5. Kumbukumbu ya quiz za dakika 5 (kila mtu anaona matokeo yake tu)
create table if not exists public.quiz_results (
  id bigint generated always as identity primary key,
  uid uuid not null references auth.users(id) on delete cascade default auth.uid(),
  name text,
  quiz_title text,
  score int not null,
  total int not null,
  questions jsonb not null default '[]',
  answers jsonb not null default '{}',
  taken_at timestamptz default now()
);
alter table public.quiz_results enable row level security;
drop policy if exists "own results read" on public.quiz_results;
create policy "own results read" on public.quiz_results for select to authenticated using (auth.uid() = uid);
drop policy if exists "own results insert" on public.quiz_results;
create policy "own results insert" on public.quiz_results for insert to authenticated with check (auth.uid() = uid);
create index if not exists quiz_results_uid_idx on public.quiz_results (uid, taken_at desc);
