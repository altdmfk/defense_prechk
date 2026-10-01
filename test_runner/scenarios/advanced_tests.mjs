import { testScenario } from '../core/runner.mjs';
import { ApiClient } from '../core/client.mjs';
import { AuthContext } from '../fixtures/auth_context.mjs';
import { ResourceSeeder } from '../fixtures/resource_seed.mjs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { SecurityAssertError } from '../core/client.mjs';

import { apiClient, auth, seeder } from '../core/shared.mjs';
const HMAC_SECRET = process.env.HMAC_SECRET || 'dummy_secret';

testScenario('Wave 4', 'restore_changed_note', '복구 엔드포인트 호출 시 원본 무결성 검증', async () => {
  const original = "Original";
  const note = await seeder.createTestNote(auth.getTokenA(), { content: original });
  await apiClient.fetchApi('PUT', `/api/notes/${note.id}`, auth.getTokenA(), { content: "Corrupted" });
  await apiClient.fetchApi('POST', `/api/notes/${note.id}/restore`, auth.getTokenA());
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${note.id}`, auth.getTokenA());
  assert.equal(verifyRes.data.content, original, '복구된 데이터가 바이트 단위로 일치해야 합니다.');
});

testScenario('Wave 4', 'restore_deleted_note', '삭제 데이터 복원 및 권한 유지 검증', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: "To be deleted" });
  
  // 삭제 수행
  await apiClient.fetchApi('DELETE', `/api/notes/${note.id}`, auth.getTokenA());
  
  // 복구 요청
  const res = await apiClient.fetchApi('POST', `/api/notes/${note.id}/restore`, auth.getTokenA());
  apiClient.assertStatus(res.status, [200, 201], '삭제된 노트의 복구가 성공해야 합니다.');

  // Strict Pre-condition Assert: 데이터가 실제로 복구되었는지 User A로 먼저 확인
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${note.id}`, auth.getTokenA());
  if (verifyRes.status !== 200) {
    throw new SecurityAssertError(`복구 API가 200을 반환했으나 실제 데이터가 복원되지 않음 (Functional Failure). 상태코드: ${verifyRes.status}`, 'FAIL');
  }

  // 데이터가 정상 복구되었다면, User B가 접근할 수 없는지(권한 방어) 확인
  const hackRes = await apiClient.fetchApi('PUT', `/api/notes/${note.id}`, auth.getTokenB(), { content: 'Hack after restore' });
  apiClient.assertStatus(hackRes.status, [403, 404], '복구된 데이터에 대한 타인(User B)의 접근은 차단되어야 합니다.');
});

testScenario('Wave 4', 'restore_defense_replay', '복구 후 이전 단계 대표 시나리오 재검증', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: "Replay" });
  await apiClient.fetchApi('POST', `/api/notes/${note.id}/restore`, auth.getTokenA());
  const hackRes = await apiClient.fetchApi('PUT', `/api/notes/${note.id}`, auth.getTokenB(), { content: 'Hack' });
  apiClient.assertStatus(hackRes.status, [403, 404], '복구된 후에도 접근 통제가 정상 작동해야 합니다.');
});

testScenario('Wave 4', 'unsigned_client_request', '서명 없는 클라이언트 보호 요청 거부', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: 'Valid Original Content' });
  const unsignedBody = { content: 'Hacked without signature' };
  const res = await apiClient.fetchApi('PUT', `/api/notes/${note.id}`, auth.getTokenA(), unsignedBody, { 'X-Signature': '' });
  apiClient.assertStatus(res.status, [400, 401, 403], '서명 누락 시 요청이 거부되어야 합니다.');

  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${note.id}`, auth.getTokenA());
  apiClient.assertImmutable(note, verifyRes.data, ['content']);
});

testScenario('Wave 4', 'signed_path_tamper', '서명 후 URL 경로 변조 감지', async () => {
  const note = await seeder.createTestNote(auth.getTokenA(), { content: 'Valid Original Content' });
  const otherNote = await seeder.createTestNote(auth.getTokenA(), { content: 'Other Target' });

  // Generate valid HMAC for updating note
  const validBody = { content: 'Updated by Valid Signature' };
  const hmac = crypto.createHmac('sha256', HMAC_SECRET)
                     .update(`PUT:/api/notes/${note.id}:${JSON.stringify(validBody)}`)
                     .digest('hex');
  
  // Attacker uses note's signature but changes URL to target otherNote
  const res = await apiClient.fetchApi('PUT', `/api/notes/${otherNote.id}`, auth.getTokenA(), validBody, { 'X-Signature': hmac });
  apiClient.assertStatus(res.status, [400, 401, 403], '경로 변조는 서명 불일치로 거절되어야 합니다.');

  // Verify otherNote is intact
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${otherNote.id}`, auth.getTokenA());
  apiClient.assertImmutable(otherNote, verifyRes.data, ['content']);
});

testScenario('Wave 4', 'signed_body_tamper', '서명 후 페이로드 변조 감지', async () => {
  // 1. Create a REAL target resource
  const note = await seeder.createTestNote(auth.getTokenA(), { content: 'Valid Original Content' });
  
  // 2. Generate valid HMAC for a PUT request
  const validBody = { content: 'Updated by Valid Signature' };
  const hmac = crypto.createHmac('sha256', HMAC_SECRET)
                     .update(`PUT:/api/notes/${note.id}:${JSON.stringify(validBody)}`)
                     .digest('hex');
  
  // 3. Attacker alters ONLY the body, keeps the original signature
  const tamperedBody = { content: 'Updated by Attacker (Tampered)' };
  const res = await apiClient.fetchApi('PUT', `/api/notes/${note.id}`, auth.getTokenA(), tamperedBody, { 'X-Signature': hmac });
  apiClient.assertStatus(res.status, [400, 401, 403], 'Tampered payload must be strictly rejected');
  
  // 4. VERIFY IMMUTABILITY: The original data MUST remain intact
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${note.id}`, auth.getTokenA());
  apiClient.assertImmutable(note, verifyRes.data, ['content']);
});
