import { testScenario } from '../core/runner.mjs';
import { apiClient, auth, seeder } from '../core/shared.mjs';
import assert from 'node:assert/strict';

// ==========================================
// 1. 기기 및 이상 접근 (Device & Anomalies) 다단계 검증
// (단순 찌르기를 넘어 실제 리소스 타격 및 무결성 보존 확인)
// ==========================================

const DEVICE_SCENARIOS = [
  { id: 'unregistered_device', header: { 'X-Device-Id': 'rogue-device' }, desc: '미등록 기기 인증서 거부' },
  { id: 'missing_client_certificate', header: { 'X-Client-Cert': '' }, desc: '클라이언트 인증서 누락 시 연결 거부' },
  { id: 'device_subject_mismatch', header: { 'X-Client-Cert': 'stolen-cert-other-user' }, desc: '기기 인증서와 사용자 주체 불일치 거부' },
  { id: 'unregistered_virtual_device_rule', header: { 'X-Virtual-Device': 'unknown-vm' }, desc: '미등록 가상 기기 차단' },
  { id: 'anomalous_region_event', header: { 'X-Forwarded-For': '198.51.100.1' }, desc: '접속 지역(GeoIP) 급변 시 추가 검증 요구' },
  { id: 'anomalous_hour_event', header: { 'X-Simulated-Time': '03:00' }, desc: '비정상 시각 접속 시 거절' }
];

for (const s of DEVICE_SCENARIOS) {
  testScenario('Wave 3', s.id, s.desc, async () => {
    const token = auth.getTokenA();
    
    // Step 1: 정상적인 상태에서 실제 테스트 타겟 리소스 생성
    const originalNote = await seeder.createTestNote(token, { content: `Device/Anomaly Test: ${s.id}` });
    
    // Step 2: 비정상 기기/환경 헤더를 주입하여 생성된 진짜 리소스를 강제 변조(PUT) 시도
    const attackRes = await apiClient.fetchApi('PUT', `/api/notes/${originalNote.id}`, token, { content: 'Hacked by Anomaly' }, s.header);
    
    // Step 3: 해당 공격이 기기 무결성 룰이나 이상 탐지 미들웨어에 의해 정확히 차단되어야 함
    apiClient.assertStatus(attackRes.status, [401, 403, 428, 429], `${s.id}: 비정상 기기/접근은 상태 변이를 일으킬 수 없어야 합니다.`);
    
    // Step 4: 공격 이후에도 데이터가 오염되지 않았는지(Immutability) 깊은 바이트 검증
    const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${originalNote.id}`, token);
    apiClient.assertImmutable(originalNote, verifyRes.data, ['content']);
  });
}

testScenario('Wave 3', 'anomalous_network_action', '낯선 네트워크 대량 수정 시 차단/추가 검증', async () => {
  const token = auth.getTokenA();
  // 여러 개의 실제 리소스를 생성
  const n1 = await seeder.createTestNote(token, { title: 'Bulk 1' });
  const n2 = await seeder.createTestNote(token, { title: 'Bulk 2' });
  
  // 한 번에 대량의 리소스를 비정상 헤더와 함께 삭제 시도
  const res = await apiClient.fetchApi('DELETE', '/api/notes/bulk', token, { ids: [n1.id, n2.id] }, { 'User-Agent': 'Scraper-Bot/1.0' });
  apiClient.assertStatus(res.status, [401, 403, 428, 429], '비정상 대량 삭제 요청은 임계치 통제에 의해 방어되어야 합니다.');
});

testScenario('Wave 3', 'missing_step_up', '2차 인증(MFA/Step-up) 누락 시 민감 리소스 접근 거부', async () => {
  // 일반적인 리소스 생성 후 민감한 "결제/권한" 엔드포인트 타격
  const res = await apiClient.fetchApi('POST', '/api/billing/upgrade', auth.getTokenA());
  apiClient.assertStatus(res.status, [401, 403, 428], '결제/승격 등 민감 액션은 MFA(Step-up) 검증 단계가 필수적입니다.');
});

// ==========================================
// 2. Cross-Zone / Tenant 격리 다단계 검증
// (가짜 999번 ID가 아닌 진짜 A 테넌트의 데이터를 B 테넌트가 노리는 시나리오)
// ==========================================

testScenario('Wave 3', 'cross_zone_note_read', '타 격리 구역(Tenant/Zone) 메모 조회 거부', async () => {
  // Step 1: User A (Tenant A 소속 가정)가 정상 데이터 생성
  const noteA = await seeder.createTestNote(auth.getTokenA(), { content: 'Tenant A Highly Classified' });
  
  // Step 2: Tenant B 환경에 속하는 완전히 별개의 신원(Attacker)을 동적 생성
  const tenantBUser = await auth.authenticateUser('attacker@tenant-b.local', 'pw', 'user');
  
  // Step 3: Tenant B의 토큰으로 Tenant A의 실제 존재하는 ID에 접근 시도
  const res = await apiClient.fetchApi('GET', `/api/notes/${noteA.id}`, tenantBUser.token, null, { 'X-Tenant-ID': 'tenant-B' });
  apiClient.assertStatus(res.status, [403, 404], 'SaaS 환경에서 데이터베이스 로우 레벨(RLS) 격리가 완벽히 적용되어야 합니다.');
});

testScenario('Wave 3', 'cross_zone_note_write', '타 격리 구역 메모 수정 거부 및 무결성 검증', async () => {
  const noteA = await seeder.createTestNote(auth.getTokenA(), { content: 'Cross Zone Write Test' });
  const tenantBUser = await auth.authenticateUser('attacker2@tenant-b.local', 'pw', 'user');
  
  // Tenant B의 공격자가 타 테넌트 데이터 수정 시도
  const putRes = await apiClient.fetchApi('PUT', `/api/notes/${noteA.id}`, tenantBUser.token, { content: 'Corrupted by Tenant B' }, { 'X-Tenant-ID': 'tenant-B' });
  apiClient.assertStatus(putRes.status, [403, 404], '타 격리 구역의 데이터를 수정하는 행위는 차단되어야 합니다.');
  
  // 무결성 검증
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${noteA.id}`, auth.getTokenA());
  apiClient.assertImmutable(noteA, verifyRes.data, ['content']);
});

testScenario('Wave 3', 'cross_zone_note_list', '타 격리 구역 목록 격리 검증 (데이터 혼선 방지)', async () => {
  const tenantCUser = await auth.authenticateUser('userC@tenant-c.local', 'pw', 'user');
  // Tenant C의 계정으로 목록 조회
  const res = await apiClient.fetchApi('GET', '/api/notes', tenantCUser.token, null, { 'X-Tenant-ID': 'tenant-C' });
  
  apiClient.assertStatus(res.status, 200, '목록 조회 자체는 가능해야 합니다.');
  // Tenant A나 B가 만든 데이터가 섞여 들어오지 않아야 함
  assert.equal(Array.isArray(res.data) && res.data.length === 0, true, '새로운 테넌트의 데이터 목록은 완전히 비어있고 격리되어야 합니다.');
});

// ==========================================
// 3. 동시 다발 및 경쟁 상태 (Race Condition / Concurrency)
// ==========================================

testScenario('Wave 3', 'doppelganger_detection', '동시 다발 세션 이상 접근 탐지 (Race Condition 락 검증)', async () => {
  const token = auth.getTokenA();
  const note = await seeder.createTestNote(token, { content: 'Concurrency Baseline' });
  
  // Step 1: 완전히 동일한 토큰으로 밀리초 단위의 동시 다발적 쓰기/수정 폭격 (Promise.all)
  const reqs = Array.from({ length: 5 }).map((_, idx) => 
    apiClient.fetchApi('PUT', `/api/notes/${note.id}`, token, { content: `Race Condition Payload ${idx}` })
  );
  
  const results = await Promise.all(reqs);
  const successCount = results.filter(r => r.status === 200 || r.status === 201).length;
  
  // Step 2: 서버가 비관적 락(Pessimistic Lock)이나 Rate Limit, Doppelganger 방어 로직이 있다면 5개가 모두 성공할 수 없음
  if (successCount === 5) {
    throw new Error(`동시 다발적 비정상 요청 5개가 전부 성공(200)했습니다. Race Condition 보호(Lock/Rate-limit)가 존재하지 않습니다.`);
  }
});
