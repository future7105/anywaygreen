-- =====================================================================
-- 어차피그린 파일럿 — Supabase 설정 SQL (v2)
-- 사용법: Supabase 대시보드 > SQL Editor > New query 에 전체 붙여넣고 Run
-- 여러 번 실행해도 안전합니다. 운영자 비밀번호는 여기 적지 않고,
-- 사이트 맨 아래 '운영진' 화면에서 처음 들어갈 때 직접 정합니다.
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- 1) 모든 데이터를 담는 표 하나 (path = '컬렉션/문서ID')
create table if not exists public.ag_docs (
  path       text primary key,
  col        text not null,
  data       jsonb not null,
  updated_at timestamptz not null default now()
);
create index if not exists ag_docs_col_idx on public.ag_docs (col);

-- 2) 보안 정책
--    private(실명·연락처·PIN): 누구도 직접 읽기·수정 불가 (신청 시 추가만 가능)
--    config·crews·notify·payouts: 운영자 비밀번호 함수로만 쓰기 가능
alter table public.ag_docs enable row level security;
drop policy if exists ag_select on public.ag_docs;
drop policy if exists ag_insert on public.ag_docs;
drop policy if exists ag_update on public.ag_docs;
drop policy if exists ag_delete on public.ag_docs;
create policy ag_select on public.ag_docs for select
  using (col <> 'private');
create policy ag_insert on public.ag_docs for insert
  with check (col not in ('config', 'crews', 'notify', 'payouts'));
create policy ag_update on public.ag_docs for update
  using (col not in ('private', 'config', 'crews', 'notify', 'payouts'))
  with check (col not in ('private', 'config', 'crews', 'notify', 'payouts'));
create policy ag_delete on public.ag_docs for delete
  using (col not in ('private', 'config', 'crews', 'notify', 'payouts'));

-- 3) 운영자 비밀번호 보관 (아무도 직접 읽을 수 없는 표)
create table if not exists public.ag_secret (k text primary key, v text not null);
alter table public.ag_secret enable row level security;

-- 4) 참가자 로그인 확인 (코드 + PIN 해시가 맞는지만 true/false)
create or replace function public.ag_login(p_code text, p_hash text)
returns boolean language sql security definer set search_path = public as $$
  select exists (select 1 from public.ag_docs
                 where path = 'private/' || p_code and data->>'pinHash' = p_hash);
$$;

-- 5) 운영자 비밀번호: 존재 여부 / 최초 설정 / 확인
create or replace function public.ag_admin_exists()
returns boolean language sql security definer set search_path = public as $$
  select exists (select 1 from public.ag_secret where k = 'admin_pw_sha256');
$$;

create or replace function public.ag_admin_setup(pw text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if length(coalesce(pw, '')) < 8 then return false; end if;
  insert into public.ag_secret (k, v)
  values ('admin_pw_sha256', encode(extensions.digest(pw, 'sha256'), 'hex'))
  on conflict (k) do nothing;
  return found;
end $$;

create or replace function public.ag_admin_check(pw text)
returns boolean language sql security definer set search_path = public as $$
  select exists (select 1 from public.ag_secret
                 where k = 'admin_pw_sha256' and v = encode(extensions.digest(coalesce(pw, ''), 'sha256'), 'hex'));
$$;

-- 6) 운영자만: 실명·연락처 열람, 운영 데이터 쓰기·삭제
create or replace function public.ag_private(pw text)
returns table (path text, data jsonb) language sql security definer set search_path = public as $$
  select d.path, d.data - 'pinHash' from public.ag_docs d
  where d.col = 'private' and public.ag_admin_check(pw);
$$;

create or replace function public.ag_admin_set(pw text, p_path text, p_col text, p_data jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.ag_admin_check(pw) then raise exception 'admin only'; end if;
  insert into public.ag_docs (path, col, data, updated_at) values (p_path, p_col, p_data, now())
  on conflict (path) do update set data = excluded.data, col = excluded.col, updated_at = now();
end $$;

create or replace function public.ag_admin_delete(pw text, p_path text)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.ag_admin_check(pw) then raise exception 'admin only'; end if;
  delete from public.ag_docs where path = p_path;
end $$;

grant execute on function public.ag_login(text, text) to anon;
grant execute on function public.ag_admin_exists() to anon;
grant execute on function public.ag_admin_setup(text) to anon;
grant execute on function public.ag_admin_check(text) to anon;
grant execute on function public.ag_private(text) to anon;
grant execute on function public.ag_admin_set(text, text, text, jsonb) to anon;
grant execute on function public.ag_admin_delete(text, text) to anon;

-- 7) 실시간 반영 (다른 사람이 올린 인증·랭킹이 바로 보이게)
do $$ begin
  alter publication supabase_realtime add table public.ag_docs;
exception when duplicate_object then null; end $$;
