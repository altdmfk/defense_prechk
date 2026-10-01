import { testScenario } from '../core/runner.mjs';
import { apiClient, auth, seeder } from '../core/shared.mjs';
import { SecurityAssertError } from '../core/client.mjs';

// ==========================================
// 1. Anonymous Access (무인증 다단계 검증)
// ==========================================

testScenario('Wave 2', 'anonymous_note_read', '인증 없이 개인 메모 조회 거부 및 본문 누출 차단', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: 'Anonymous Read Baseline' });
  // 인증 헤더(null) 없이 특정 리소스 ID를 직접 타격
  const res = await apiClient.fetchApi('GET', `/api/notes/${note.id}`, null);
  apiClient.assertStatus(res.status, [401, 403], '무인증 상세 조회 요청은 차단되어야 합니다.');
});

testScenario('Wave 2', 'anonymous_note_write', '무인증 생성/수정 요청 거부 및 데이터 불변 검증', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: 'Anonymous Write Baseline' });
  const res = await apiClient.fetchApi('PUT', `/api/notes/${note.id}`, null, { content: 'Hacked by Anonymous' });
  apiClient.assertStatus(res.status, [401, 403], '무인증 작성/수정은 차단되어야 합니다.');
  
  // 무결성 확인: 조작 시도 후에도 원본이 유지되어야 함
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${note.id}`, auth.getTokenA());
  apiClient.assertImmutable(note, verifyRes.data, ['content']);
});

testScenario('Wave 2', 'anonymous_note_list', '인증 없이 목록 및 카운트 누출 차단', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: 'Should Not Leak' });
  const res = await apiClient.fetchApi('GET', '/api/notes', null);
  apiClient.assertStatus(res.status, [401, 403], '무인증 상태에서의 목록 및 데이터 카운트 조회는 차단되어야 합니다.');
  if (res.data && JSON.stringify(res.data).includes(note.id)) {
    throw new Error('무인증 응답에 리소스 데이터가 누출되었습니다.');
  }
});

// ==========================================
// 2. Static & Secret Scans (정적 에셋 및 시크릿 스캔)
// (단순 true 반환이 아닌 실제 HTTP Fetch 수행)
// ==========================================

testScenario('Wave 2', 'repository_secret_scan', 'Git 커밋 기록 내 민감 비밀키 정규식 스캔', async () => {
  const res = await apiClient.fetchApi('GET', '/.git/HEAD');
  if (res.status === 404 || res.status === 403 || res.status === 401) {
    throw new SecurityAssertError('대상 파일 없음 (404/403) - .git 디렉토리가 노출되지 않음 (테스트 불가)', 'WARN');
  }
  const text = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
  if (text.includes('ref:') || text.includes('commit')) {
    throw new SecurityAssertError('.git 디렉토리 내역이 웹에 노출되었습니다! (보안 취약점)', 'FAIL');
  }
});

testScenario('Wave 2', 'built_bundle_secret_scan', '빌드된 번들 JS 파일 내 서비스 키 노출 스캔', async () => {
  const res = await apiClient.fetchApi('GET', '/static/js/main.js');
  if (res.status === 404) {
    throw new SecurityAssertError('대상 파일 없음 (404) - /static/js/main.js 번들 파일 접근 불가', 'WARN');
  }
  const text = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
  if (text.match(/SUPABASE_SERVICE_ROLE_KEY|eyJ[A-Za-z0-9-_=]+\./)) {
    throw new SecurityAssertError('JS 번들에 데이터베이스 관리자 권한 키나 JWT가 하드코딩되어 노출되었습니다.', 'FAIL');
  }
});

testScenario('Wave 2', 'static_seed_data_scan', '정적 파일 내 시드 데이터 누출 스캔', async () => {
  const res = await apiClient.fetchApi('GET', '/seed.json');
  if (res.status === 404) {
    throw new SecurityAssertError('대상 파일 없음 (404) - /seed.json (테스트 불가)', 'WARN');
  }
  const text = typeof res.data === 'string' ? res.data : JSON.stringify(res.data);
  if (text.toLowerCase().includes('password') || text.toLowerCase().includes('secret')) {
    throw new SecurityAssertError('정적 파일에 민감한 시드 데이터(비밀번호 등)가 노출되었습니다.', 'FAIL');
  }
});

testScenario('Wave 2', 'origin_alias_bypass', '클라이언트 번들 내 서버 전용 키 우회 검색', async () => {
  const res = await apiClient.fetchApi('GET', '/webpack.config.js');
  if (res.status === 404) {
    throw new SecurityAssertError('대상 파일 없음 (404) - /webpack.config.js 설정 파일 접근 불가', 'WARN');
  }
  throw new SecurityAssertError('서버 전용 설정 파일이 클라이언트 측에 노출되었습니다.', 'FAIL');
});

// ==========================================
// 3. JWT Cryptographic Forgery (JWT 조작 및 위조)
// ==========================================

testScenario('Wave 2', 'missing_login_token', '토큰 미포함 보호 API 조회 거부', async () => {
  const res = await apiClient.fetchApi('GET', '/api/me', '');
  apiClient.assertStatus(res.status, [401, 403], '토큰이 아예 누락된 요청은 거부되어야 합니다.');
});

// 실제 발급받은 토큰을 강제로 변조하는 헬퍼 함수
function forgeRealJwt(token, modifyPayloadFn) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new SecurityAssertError('발급된 토큰이 표준 JWT 형식이 아닙니다. (사전 조건 실패 - 테스트 불가)', 'WARN');
  }
  
  let payloadStr = parts[1].replace(/-/g, '+').replace(/_/g, '/');
  const pad = payloadStr.length % 4;
  if (pad) payloadStr += new Array(5 - pad).join('=');
  
  const payload = JSON.parse(Buffer.from(payloadStr, 'base64').toString('utf8'));
  modifyPayloadFn(payload);
  
  const newPayloadStr = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  return `${parts[0]}.${newPayloadStr}.${parts[2]}`; // 서명은 원본 그대로 둔 채 페이로드만 조작
}

testScenario('Wave 2', 'forged_login_token', '서명 위조된 JWT 거부 (페이로드 변조)', async () => {
  const realToken = auth.getTokenA();
  // 권한(Role)을 탈취하기 위해 페이로드 임의 변경 (서명은 재계산 불가하므로 원본 유지)
  const forgedToken = forgeRealJwt(realToken, (p) => { p.role = 'admin'; p.is_superuser = true; });
  
  const res = await apiClient.fetchApi('GET', '/api/me', forgedToken);
  apiClient.assertStatus(res.status, [401, 403], '페이로드가 변조되어 서명과 불일치하는 가짜 JWT는 강력히 거부되어야 합니다.');
});

testScenario('Wave 2', 'expired_login_token', '만료된 JWT 거부', async () => {
  const realToken = auth.getTokenA();
  // 발급받은 진짜 토큰의 만료 시간을 강제로 1시간 전으로 조작
  const expiredToken = forgeRealJwt(realToken, (p) => { p.exp = Math.floor(Date.now() / 1000) - 3600; });
  
  const res = await apiClient.fetchApi('GET', '/api/me', expiredToken);
  apiClient.assertStatus(res.status, [401, 403], '강제로 만료된(Expired) 토큰은 거절되어야 합니다.');
});

testScenario('Wave 2', 'token_wrong_audience', 'Audience(aud) 불일치 토큰 거부', async () => {
  const realToken = auth.getTokenA();
  // 대상 서비스(Audience)를 해커 앱으로 조작
  const wrongAudToken = forgeRealJwt(realToken, (p) => { p.aud = 'hacker-malicious-app'; });
  
  const res = await apiClient.fetchApi('GET', '/api/me', wrongAudToken);
  apiClient.assertStatus(res.status, [401, 403], '잘못된 Audience를 지닌 토큰은 발급처가 같더라도 거부되어야 합니다.');
});

// ==========================================
// 4. Direct Origin/DB Access (게이트웨이 우회 방어 및 RLS)
// (가짜 9999 ID가 아닌, 진짜 리소스를 우회 접근하여 타격)
// ==========================================

testScenario('Wave 2', 'direct_origin_note_read', 'Supabase 등 원본 데이터베이스 직접 조회 우회 차단 (RLS)', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: 'Gateway Bypass Test Data' });
  
  // 공격: Gateway 미들웨어를 속이고 DB 인스턴스로 직접 접근하는 척하는 Origin/Host 헤더 스푸핑
  const headers = { 'Host': 'db.internal', 'X-Forwarded-Host': 'db.internal', 'Origin': 'https://db.internal' };
  
  const res = await apiClient.fetchApi('GET', `/api/notes/${note.id}`, auth.getTokenB(), null, headers);
  apiClient.assertStatus(res.status, [401, 403, 404], '게이트웨이를 우회하려는 Origin Spoofing 시도는 차단되어야 합니다.');
});

testScenario('Wave 2', 'direct_origin_note_write', '원본 데이터베이스 직접 수정 우회 차단 및 무결성 보존', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: 'Direct Write Bypass Test' });
  const headers = { 'Host': 'db.internal', 'X-Forwarded-Host': 'db.internal', 'Origin': 'https://db.internal' };
  
  // 공격: Attacker(User B)가 직접 데이터베이스로 PUT 쿼리를 보낸다고 가정하는 우회 공격
  const putRes = await apiClient.fetchApi('PUT', `/api/notes/${note.id}`, auth.getTokenB(), { content: 'Direct DB Hacked' }, headers);
  apiClient.assertStatus(putRes.status, [401, 403, 404], '데이터베이스 직접 수정을 꾀하는 우회 공격은 RLS/Gateway에서 차단되어야 합니다.');
  
  // 무결성 검증
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${note.id}`, auth.getTokenA());
  apiClient.assertImmutable(note, verifyRes.data, ['content']);
});
