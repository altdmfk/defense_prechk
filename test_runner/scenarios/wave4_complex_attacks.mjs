import { testScenario } from '../core/runner.mjs';
import { apiClient, auth, seeder } from '../core/shared.mjs';
import assert from 'node:assert/strict';

// ==========================================
// 복합 공격 (Combined Edge Attacks) 
// 방어선(미들웨어)들이 중첩되었을 때 올바르게 가장 높은 우선순위의 차단이 작동하는지 검증
// ==========================================

testScenario('Wave 4', 'combined_anonymous_owner_attack', '무인증(Anonymous) + 타인 리소스(BOLA) 복합 타격 및 무결성 검증', async () => {
  // Step 1: 정상적인 상태에서 타겟(희생자) 리소스 생성
  const victimNote = await seeder.createTestNote(auth.getTokenA(), { content: 'Confidential Victim Data' });
  
  // Step 2: 공격자가 토큰 없이(null) 즉 무인증 상태로 특정된 희생자 ID를 타격
  // 과거처럼 '9999_foreign' 가짜 ID를 쓰지 않음!
  const attackRes = await apiClient.fetchApi('PUT', `/api/notes/${victimNote.id}`, null, { content: 'Overwritten by Anonymous Hacker' });
  
  // Step 3: BOLA 체크 이전에 이미 Gateway 단계에서 인증 없음으로 튕겨야 함
  apiClient.assertStatus(attackRes.status, [401, 403], '무인증 상태의 타인 리소스 조작 시도는 강력하게 차단되어야 합니다.');

  // Step 4: 공격 시도 이후에도 타겟 리소스의 원본 바이트가 안전하게 보존되었는지 재확인 (Immutability)
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${victimNote.id}`, auth.getTokenA());
  apiClient.assertImmutable(victimNote, verifyRes.data, ['content']);
});

testScenario('Wave 4', 'combined_device_revocation_attack', '폐기된 신원(Revoked) + 미등록 기기(Rogue Device) 복합 타격 검증', async () => {
  // Step 1: 희생자 역할의 임시 사용자 셋업 후 리소스 생성
  const tempUser = await auth.authenticateUser('complex_victim@test.local', 'pw123', 'user');
  const targetNote = await seeder.createTestNote(tempUser.token, { content: 'Sensitive Device Data' });

  // Step 2: 해당 세션(토큰)을 로그아웃을 통해 명시적으로 파기 (Revocation)
  await apiClient.fetchApi('POST', '/api/auth/logout', tempUser.token); 
  
  // Step 3: 공격자가 폐기된 토큰을 탈취한 후, 자신이 쓰는 "미등록 해킹 기기" 환경에서 타격 시도
  const rogueHeaders = { 'X-Device-Id': 'stolen-rogue-vm-99' };
  const attackRes = await apiClient.fetchApi('PUT', `/api/notes/${targetNote.id}`, tempUser.token, { content: 'Attacked via stolen token' }, rogueHeaders);
  
  // Step 4: 세션 폐기와 기기 불일치 중 어느 방어선이든 반응하여 접근을 차단해야 함
  apiClient.assertStatus(attackRes.status, [401, 403], '폐기된 토큰과 인가되지 않은 기기의 결합 공격은 원천 차단되어야 합니다.');

  // Step 5: 무결성 교차 검증 (새롭게 로그인해서 원본 확인)
  const refreshedUser = await auth.authenticateUser('complex_victim@test.local', 'pw123', 'user');
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${targetNote.id}`, refreshedUser.token);
  apiClient.assertImmutable(targetNote, verifyRes.data, ['content']);
});

testScenario('Wave 4', 'combined_restore_signature_attack', '복구 직후 무서명(Unsigned) + 구역 침범(Cross-Zone) 복합 타격 검증', async () => {
  // Step 1: User A가 정상적인 데이터를 생성하고 임의 오염시킴
  const originalData = "Golden Record";
  const noteA = await seeder.createTestNote(auth.getTokenA(), { content: originalData });
  await apiClient.fetchApi('PUT', `/api/notes/${noteA.id}`, auth.getTokenA(), { content: "Corrupted Record" });
  
  // Step 2: User B(Attacker)가 User A의 리소스를 복구(Restore)시키려 시도하되,
  // 1) 필수인 서명(X-Signature)을 누락하고
  // 2) 타 테넌트 헤더를 달아서 복합적인 로직 혼선을 유도
  const evilHeaders = { 
    'X-Tenant-ID': 'admin-zone', 
    'X-Signature': '' // 서명 우회 시도
  };
  
  const attackRes = await apiClient.fetchApi('POST', `/api/notes/${noteA.id}/restore`, auth.getTokenB(), { force: true }, evilHeaders);
  
  // Step 3: 무서명, BOLA, Cross-Zone 중 어떤 것이든 걸려서 철벽 방어가 되어야 함
  apiClient.assertStatus(attackRes.status, [400, 401, 403], '서명 누락 및 교차 구역 헤더 주입이 동반된 악의적 복구 시도는 차단되어야 합니다.');

  // Step 4: 복구가 실행되지 않고 여전히 "Corrupted Record" 상태로 남아있어야 함 (공격 실패로 인한 상태 유지)
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${noteA.id}`, auth.getTokenA());
  assert.equal(verifyRes.data.content, "Corrupted Record", '악의적 공격자의 복구 시도는 무시되어 상태가 변하지 않아야 합니다.');
});
