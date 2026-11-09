-- =====================================================================
-- 어차피그린 파일럿 — Supabase 설정 SQL
-- 사용법: Supabase 대시보드 > SQL Editor > New query 에 전체 붙여넣고 Run
-- 실행 전에 아래 '여기에_운영자_비밀번호' 부분만 팀이 정한 비밀번호로 바꾸세요.
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

-- 2) 보안 정책: 'private'(실명·연락처·PIN)는 누구도 직접 읽을 수 없음
alter table public.ag_docs enable row level security;
drop policy if exists ag_select on public.ag_docs;
drop policy if exists ag_insert on public.ag_docs;
drop policy if exists ag_update on public.ag_docs;
drop policy if exists ag_delete on public.ag_docs;
create policy ag_select on public.ag_docs for select using (col <> 'private');
create policy ag_insert on public.ag_docs for insert with check (true);
create policy ag_update on public.ag_docs for update using (col <> 'private') with check (col <> 'private');
create policy ag_delete on public.ag_docs for delete using (col <> 'private');

-- 3) 운영자 비밀번호 보관 (아무도 직접 읽을 수 없는 표)
create table if not exists public.ag_secret (k text primary key, v text not null);
alter table public.ag_secret enable row level security;
insert into public.ag_secret (k, v)
values ('admin_pw_sha256', encode(extensions.digest('여기에_운영자_비밀번호', 'sha256'), 'hex'))
on conflict (k) do update set v = excluded.v;

-- 4) 참가자 로그인 확인 (코드 + PIN 해시가 맞는지만 true/false로 알려줌)
create or replace function public.ag_login(p_code text, p_hash text)
returns boolean language sql security definer set search_path = public as $$
  select exists (select 1 from public.ag_docs
                 where path = 'private/' || p_code and data->>'pinHash' = p_hash);
$$;

-- 5) 운영자 비밀번호 확인
create or replace function public.ag_admin_check(pw text)
returns boolean language sql security definer set search_path = public as $$
  select exists (select 1 from public.ag_secret
                 where k = 'admin_pw_sha256' and v = encode(extensions.digest(pw, 'sha256'), 'hex'));
$$;

-- 6) 운영자만 실명·연락처 열람
create or replace function public.ag_private(pw text)
returns table (path text, data jsonb) language sql security definer set search_path = public as $$
  select d.path, d.data - 'pinHash' from public.ag_docs d
  where d.col = 'private' and public.ag_admin_check(pw);
$$;

grant execute on function public.ag_login(text, text) to anon;
grant execute on function public.ag_admin_check(text) to anon;
grant execute on function public.ag_private(text) to anon;

-- 7) 실시간 반영 (다른 사람이 올린 인증·랭킹이 바로 보이게)
do $$ begin
  alter publication supabase_realtime add table public.ag_docs;
exception when duplicate_object then null; end $$;
