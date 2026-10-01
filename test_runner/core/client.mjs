/**
 * API 요청을 표준화하고 단언(Assertion) 기능을 제공하는 클라이언트 코어
 */

// 커스텀 에러 클래스 도입 (3-Tier Reporting 지원)
export class SecurityAssertError extends Error {
  constructor(message, type = 'FAIL') {
    super(message);
    this.name = 'SecurityAssertError';
    this.type = type; // 'FAIL' | 'WARN'
  }
}

export class ApiClient {
  constructor(baseUrl) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async fetchApi(method, route, token = null, body = null, extraHeaders = {}) {
    const headers = { ...extraHeaders };
    
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    
    if (body && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const options = {
      method,
      headers,
      redirect: 'manual'
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const targetUrl = `${this.baseUrl}${route}`;

    try {
      const response = await fetch(targetUrl, options);
      const status = response.status;
      const responseHeaders = response.headers;
      
      let data = null;
      const text = await response.text();
      
      try {
        if (text) {
          data = JSON.parse(text);
        }
      } catch (e) {
        data = text;
      }

      if (status === 200 && typeof data === 'string' && 
         (data.trim().toLowerCase().startsWith('<!doctype html') || data.trim().toLowerCase().startsWith('<html'))) {
        return { status: 404, data: 'Not Found (HTML Returned)', headers: responseHeaders };
      }

      return { status, data, headers: responseHeaders };
    } catch (error) {
      // 네트워크 연결 거절(Connection Refused) 등은 WARN 처리
      throw new SecurityAssertError(`네트워크 오류 또는 연결 실패: ${error.message}`, 'WARN');
    }
  }

  assertImmutable(original, current, keysToCompare) {
    if (!original || !current) {
      throw new SecurityAssertError(`비교할 데이터가 누락되었습니다. (API 미구현 가능성)`, 'WARN');
    }

    for (const key of keysToCompare) {
      if (JSON.stringify(original[key]) !== JSON.stringify(current[key])) {
        throw new SecurityAssertError(
          `데이터 변조 감지! 속성 '${key}'가 무단으로 변경되었습니다. (예상 원본: ${JSON.stringify(original[key])}, 실제 현재값: ${JSON.stringify(current[key])})`,
          'FAIL'
        );
      }
    }
  }

  assertStatus(actual, expected, message = '') {
    const isMatch = Array.isArray(expected) ? expected.includes(actual) : actual === expected;
    if (isMatch) return; // PASS

    // 예상 상태 코드가 아닌데, 실제 코드가 404(Not Found)나 501(Not Implemented)인 경우 API 자체가 없다고 간주 (WARN)
    // 단, 404를 "방어 성공(예상 상태)"으로 기대한 경우에는 위 isMatch에서 PASS 처리됨.
    if (actual === 404) {
      throw new SecurityAssertError(`API 미구현 (404) - 테스트 불가. ${message}`, 'WARN');
    }
    
    // 500 에러 계열은 서버 크래시이므로 WARN 또는 FAIL. 여기선 FAIL로 간주하여 취약점 노출 위험 경고.
    if (actual >= 500) {
       throw new SecurityAssertError(`서버 내부 오류 (${actual}) - 예외 처리 미흡 또는 크래시 발생. ${message}`, 'FAIL');
    }

    // 그 외는 실제 방어 실패(FAIL)
    throw new SecurityAssertError(
      `상태코드 불일치 (방어 실패). 예상: ${expected}, 실제: ${actual}. ${message}`,
      'FAIL'
    );
  }
}
