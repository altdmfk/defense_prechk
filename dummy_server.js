const http = require('http');

const server = http.createServer((req, res) => {
  console.log(`[Dummy Server] Received ${req.method} request to ${req.url}`);
  
  // CORS 허용
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    res.end();
    return;
  }

  // 1. 번들 보안 (Bundle Hygiene) - 취약점 노출
  if (req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>테스트 사이트</h1><script src="/bundle.js"></script></body></html>');
    return;
  }
  
  if (req.url === '/bundle.js') {
    res.writeHead(200, { 'Content-Type': 'application/javascript' });
    // 비밀키 및 하드코딩된 데이터가 번들에 그대로 남아있는 취약점
    res.end('const config = { key: "SUPABASE_SERVICE_ROLE_KEY", token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_token.sig" };\nconst data = "private note";');
    return;
  }

  // API 응답을 위한 유틸
  const sendJson = (status, data) => {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  };

  // 2. 세션 무효화 (Session Revocation) - 취약점
  if (req.url === '/api/auth/logout' && req.method === 'POST') {
    // 로그아웃 요청을 받지만 실제 서버 상태(Redis 등)에서 세션을 만료시키지 않음
    return sendJson(200, { message: "로그아웃 성공 (하지만 토큰은 무효화되지 않음)" });
  }

  if (req.url === '/api/protected' && req.method === 'GET') {
    // 토큰의 만료 여부나 로그아웃(블랙리스트) 여부를 전혀 확인하지 않음
    return sendJson(200, { message: "보호된 자원 접근 성공 (취약함)" });
  }

  // 3. RBAC (역할 기반 권한 통제) - 취약점
  if (req.url === '/api/notice' && req.method === 'POST') {
    // 학생 토큰(User)인지 강사 토큰(Admin)인지 구별하지 않고 무조건 200 OK 처리
    return sendJson(200, { message: "공지사항 수정 성공 (학생도 수정 가능 - 취약함)" });
  }

  // 4. IDOR / BOLA (교차 테넌트 접근) - 취약점
  if (req.url.match(/^\/api\/notes\/(\d+)$/)) {
    // 요청한 유저가 해당 노트(99999 등 타인의 노트)의 소유자인지 검증하지 않음
    return sendJson(200, { id: 99999, content: "타인의 비공개 노트 내용 (취약함)" });
  }

  // 5. 일반 엔드포인트 (기타 인증, 기기 검증, 변조 등) - 취약점
  if (req.url === '/api/notes') {
    // 토큰이 없거나 만료되었거나, 디바이스 아이디가 다르거나, 
    // 서명이 변조되었는지 여부를 일절 검증하지 않고 허용
    if (req.method === 'GET' || req.method === 'POST') {
      return sendJson(200, { 
        status: "success", 
        message: "토큰, 서명, Origin 검증 없이 요청 허용됨 (취약함)" 
      });
    }
  }

  res.writeHead(404);
  res.end('Not Found');
});

server.listen(4000, () => {
  console.log('--- 취약한 더미 서버 (포트 4000) ---');
  console.log('이 서버는 precheck.mjs의 41개 테스트가 요구하는 시나리오들에 대해');
  console.log('방어 기제(보안 로직)가 전무한 상태를 명시적으로 구현하고 있습니다.');
});
