import { SecurityAssertError } from '../core/client.mjs';

export class ResourceSeeder {
  constructor(apiClient) {
    this.apiClient = apiClient;
  }

  async createTestNote(token, overrideData = {}) {
    const payload = {
      title: "Stateful Test Note",
      content: "This is a confidential note created for state transition tests.",
      isPrivate: true,
      ...overrideData
    };

    const res = await this.apiClient.fetchApi('POST', '/api/notes', token, payload);
    
    if (res.status === 404) {
      throw new SecurityAssertError(`API 미구현 (404) - 데이터 셋업(/api/notes) 실패로 테스트 불가`, 'WARN');
    }
    
    if (res.status !== 201 && res.status !== 200) {
      throw new SecurityAssertError(`사전 리소스(Note) 생성 실패로 테스트 불가. 상태코드: ${res.status}`, 'WARN');
    }

    return res.data; 
  }

  async createTestNotice(adminToken, overrideData = {}) {
    const payload = {
      title: "Important Exam Notice",
      content: "All students must attend the exam tomorrow.",
      ...overrideData
    };

    const res = await this.apiClient.fetchApi('POST', '/api/notices', adminToken, payload);
    
    if (res.status === 404) {
      throw new SecurityAssertError(`API 미구현 (404) - 데이터 셋업(/api/notices) 실패로 테스트 불가`, 'WARN');
    }
    
    if (res.status !== 201 && res.status !== 200) {
      throw new SecurityAssertError(`사전 리소스(Notice) 생성 실패로 테스트 불가. 상태코드: ${res.status}`, 'WARN');
    }

    return res.data;
  }

  async deleteTestNote(token, noteId) {
    await this.apiClient.fetchApi('DELETE', `/api/notes/${noteId}`, token);
  }
}
