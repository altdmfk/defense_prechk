import { testScenario, beforeAll } from '../core/runner.mjs';
import { ApiClient } from '../core/client.mjs';
import { AuthContext } from '../fixtures/auth_context.mjs';
import { ResourceSeeder } from '../fixtures/resource_seed.mjs';
import assert from 'node:assert/strict';

import { apiClient, auth, seeder } from '../core/shared.mjs';

beforeAll(async () => {
  await auth.setupContext();
});

testScenario('Wave 2', 'r3_judge_owned_note', 'BOLA / IDOR (사용자 B가 사용자 A의 리소스 단건 조회 차단)', async () => {
  const noteA = await seeder.createTestNote(auth.getTokenA(), { content: 'Secret A' });
  const res = await apiClient.fetchApi('GET', `/api/notes/${noteA.id}`, auth.getTokenB());
  apiClient.assertStatus(res.status, [403, 404], 'User B는 User A의 리소스를 조회할 수 없어야 합니다.');
});

testScenario('Wave 2', 'r3_judge_owned_note_write', '타인 리소스 수정 차단 및 데이터 불변', async () => {
  const noteA = await seeder.createTestNote(auth.getTokenA(), { content: 'Secret A' });
  const putRes = await apiClient.fetchApi('PUT', `/api/notes/${noteA.id}`, auth.getTokenB(), { content: 'Hacked' });
  apiClient.assertStatus(putRes.status, [403, 404], '타인 리소스 수정은 차단되어야 합니다.');
  
  const verifyRes = await apiClient.fetchApi('GET', `/api/notes/${noteA.id}`, auth.getTokenA());
  apiClient.assertImmutable(noteA, verifyRes.data, ['content']);
});

testScenario('Wave 2', 'foreign_note_delete', '타인 리소스 삭제 차단 및 원본 보존', async () => {
  const noteA = await seeder.createTestNote(auth.getTokenA(), { content: 'Secret A' });
  const delRes = await apiClient.fetchApi('DELETE', `/api/notes/${noteA.id}`, auth.getTokenB());
  apiClient.assertStatus(delRes.status, [403, 404], '타인 리소스 삭제는 차단되어야 합니다.');
});

testScenario('Wave 3', 'student_edits_instructor_notice', 'RBAC 역할 분리 (학생 토큰 403 vs 강사 토큰 200)', async () => {
  const notice = await seeder.createTestNotice(auth.getAdminToken(), { title: 'Exam Notice' });
  const putRes = await apiClient.fetchApi('PUT', `/api/notices/${notice.id}`, auth.getTokenA(), { title: 'Hacked' });
  apiClient.assertStatus(putRes.status, [403, 404], '학생의 강사 공지 수정은 차단되어야 합니다.');
});

testScenario('Wave 3', 'revoked_identity_reuse', '세션 폐기 후 동일 토큰 재사용 차단', async () => {
  const tempUser = await auth.authenticateUser('victim1@test.local', 'pw', 'user');
  await apiClient.fetchApi('POST', '/api/auth/logout', tempUser.token);
  const reuseRes = await apiClient.fetchApi('GET', '/api/notes', tempUser.token);
  apiClient.assertStatus(reuseRes.status, 401, '폐기된 토큰의 재사용은 즉각 차단(401)되어야 합니다.');
});

testScenario('Wave 3', 'stolen_session_after_revoke', '세션 무효화 후 탈취 세션 차단 및 정상 세션 유지', async () => {
  const tempUser = await auth.authenticateUser('victim2@test.local', 'pw', 'user');
  await apiClient.fetchApi('POST', '/api/auth/logout', tempUser.token);
  const res = await apiClient.fetchApi('GET', '/api/me', tempUser.token);
  apiClient.assertStatus(res.status, 401, '탈취된 폐기 토큰 접근은 차단되어야 합니다.');
});

testScenario('Wave 3', 'revoked_lateral_route', '폐기된 세션의 수평 이동(Lateral Movement) 차단', async () => {
  const tempUser = await auth.authenticateUser('victim3@test.local', 'pw', 'user');
  await apiClient.fetchApi('POST', '/api/auth/logout', tempUser.token);
  const latRes = await apiClient.fetchApi('POST', '/api/notes', tempUser.token, { content: 'Lateral' });
  apiClient.assertStatus(latRes.status, [401, 403], '폐기된 토큰의 타 라우트 접근은 차단되어야 합니다.');
});
