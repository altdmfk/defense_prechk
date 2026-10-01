import { SecurityAssertError } from '../core/client.mjs';

export class AuthContext {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.identities = {
      userA: { token: null, id: null },
      userB: { token: null, id: null },
      admin: { token: null, id: null }
    };
  }

  async setupContext() {
    try {
      this.identities.userA = await this.authenticateUser('userA@test.local', 'passA', 'user');
      this.identities.userB = await this.authenticateUser('userB@test.local', 'passB', 'user');
      this.identities.admin = await this.authenticateUser('admin@test.local', 'passAdmin', 'admin');
    } catch (e) {
      if (e instanceof SecurityAssertError) throw e;
      throw new SecurityAssertError(`사전 인증(토큰 발급) 실패로 테스트 불가: ${e.message}`, 'WARN');
    }
  }

  async authenticateUser(email, password, role) {
    let res = await this.apiClient.fetchApi('POST', '/api/auth/login', null, { email, password });
    
    if (res.status === 401 || res.status === 404) {
      await this.apiClient.fetchApi('POST', '/api/auth/register', null, { email, password, role });
      res = await this.apiClient.fetchApi('POST', '/api/auth/login', null, { email, password });
    }

    if (res.status !== 200 && res.status !== 201) {
      throw new SecurityAssertError(`[AuthContext] ${email} 인증 실패. 상태코드: ${res.status}`, 'WARN');
    }

    return {
      token: res.data.token || res.data.access_token || res.data.session_token,
      id: res.data.user_id || res.data.id
    };
  }
  
  getTokenA() {
    if (!this.identities.userA.token) throw new SecurityAssertError("사전 인증(토큰 발급) 실패로 테스트 불가 (User A)", 'WARN');
    return this.identities.userA.token;
  }

  getTokenB() {
    if (!this.identities.userB.token) throw new SecurityAssertError("사전 인증(토큰 발급) 실패로 테스트 불가 (User B)", 'WARN');
    return this.identities.userB.token;
  }

  getAdminToken() {
    if (!this.identities.admin.token) throw new SecurityAssertError("사전 인증(토큰 발급) 실패로 테스트 불가 (Admin)", 'WARN');
    return this.identities.admin.token;
  }

  getIdA() { return this.identities.userA.id; }
  getIdB() { return this.identities.userB.id; }
}
