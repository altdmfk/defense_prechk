import fs from 'fs';
import path from 'path';
import { parseArgs } from 'util';
import { execSync } from 'child_process';

// ============================================================================
// 1. 보안 점검 항목 정의 (Hardcoded Security Checks)
// ============================================================================
const SECURITY_CHECKS = [
  { id: "anonymous_note_read", step: 1, wave: 1, name: "API 인증 우회 (GET 조회)", expected: "401 또는 403 응답 (인가 거부)" },
  { id: "anonymous_note_write", step: 1, wave: 2, name: "API 인증 우회 (POST 쓰기)", expected: "401 또는 403 응답 (인가 거부)" },
  { id: "repository_secret_scan", step: 2, wave: 1, name: "Git 히스토리 내 비밀키 유출", expected: "커밋 내역에 유출된 키 없음" },
  { id: "built_bundle_secret_scan", step: 2, wave: 2, name: "클라이언트 번들(JS) JWT 유출", expected: "번들 파일 내에 민감한 키 포함 안 됨" },
  { id: "static_seed_data_scan", step: 2, wave: 3, name: "클라이언트 번들(JS) Seed 데이터 하드코딩", expected: "API 응답이 아닌 하드코딩된 데이터 없음" },
  { id: "forged_login_token", step: 3, wave: 1, name: "위조된 JWT 토큰 서명(Signature) 검증", expected: "조작된 토큰에 대해 401/403 응답" },
  { id: "r3_judge_owned_note", step: 4, wave: 1, name: "타인 데이터 불법 접근 (BOLA/IDOR)", expected: "리소스 소유자가 아닐 시 403/404 응답" }
];

// ============================================================================
// 2. 설정 및 환경 변수 파싱 (Configuration & Env)
// ============================================================================
function loadConfig() {
  const options = {
    url: { type: 'string' },
    token: { type: 'string' },
    step: { type: 'string' },
    wave: { type: 'string' },
    'api-base': { type: 'string' }
  };
  const { values } = parseArgs({ options, strict: false });

  const envPath = path.join(process.cwd(), '.env');
  const env = {};
  if (fs.existsSync(envPath)) {
    const envFile = fs.readFileSync(envPath, 'utf8');
    envFile.split('\n').forEach(line => {
      const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
      if (match) {
        env[match[1]] = match[2].replace(/^['"]|['"]$/g, '').trim();
      }
    });
  }

  const rawUrl = values.url || env.TARGET_URL;
  if (!rawUrl) {
    console.error("오류: --url <target_url> 옵션 또는 .env 파일의 TARGET_URL 설정이 필요합니다.");
    process.exit(1);
  }

  return {
    targetUrl: rawUrl.replace(/\/$/, ''),
    userToken: values.token || env.USER_TOKEN || '',
    stepFilter: values.step ? parseInt(values.step, 10) : null,
    waveFilter: values.wave ? parseInt(values.wave, 10) : null,
    apiBase: values['api-base'] || env.API_BASE || '/api/notes'
  };
}

const config = loadConfig();

// ============================================================================
// 3. 터미널 출력 유틸리티 (Console Utilities)
// ============================================================================
const C = {
  reset: "\x1b[0m", red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m",
  blue: "\x1b[34m", cyan: "\x1b[36m", bold: "\x1b[1m"
};

function printDiagnostic(check, errorMsg, causeMsg, debugInfo = null) {
  console.log(`\n${C.red}${C.bold}❌ 방어 실패 (VULNERABILITY FOUND)${C.reset}`);
  console.log(`${C.cyan}점검 항목:${C.reset} ${check.name}`);
  console.log(`${C.cyan}예상 방어 결과:${C.reset} ${check.expected}`);
  console.log(`${C.cyan}발생한 취약점:${C.reset} ${errorMsg}`);
  console.log(`${C.cyan}해결 가이드:${C.reset} ${causeMsg}`);
  
  if (debugInfo) {
    console.log(`\n${C.yellow}--- 디버그 로그 (Debug Log) ---${C.reset}`);
    if (debugInfo.req) console.log(`${C.yellow}요청:${C.reset} ${debugInfo.req}`);
    if (debugInfo.status) console.log(`${C.yellow}응답 상태:${C.reset} ${debugInfo.status}`);
    if (debugInfo.body) console.log(`${C.yellow}응답 본문:${C.reset} ${debugInfo.body.replace(/\n/g, ' ').substring(0, 200)}...`);
    console.log(`${C.yellow}-------------------------------${C.reset}`);
  }
  console.log();
}

// ============================================================================
// 4. 네트워크 및 테스트 유틸리티 (Network & Test Helpers)
// ============================================================================
let lastDebug = null;
async function fetchApi(method, endpoint, headers = {}) {
  const url = `${config.targetUrl}${endpoint}`;
  try {
    const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json', ...headers } });
    const bodyText = await res.clone().text().catch(() => '');
    lastDebug = { req: `${method} ${url}`, status: res.status, body: bodyText };
    return res;
  } catch(err) {
    lastDebug = { req: `${method} ${url}`, status: 0, body: err.message };
    return { status: 0, text: async () => err.message };
  }
}

// ============================================================================
// 5. 공격 패턴 핸들러 모음 (Attack Strategy Handlers)
// ============================================================================
const AttackHandlers = {
  async check_anonymous_read(attackId) {
    const endpoint = attackId === 'anonymous_note_read' ? `${config.apiBase}/1` : config.apiBase;
    const res = await fetchApi('GET', endpoint);
    if (res.status !== 401 && res.status !== 403 && res.status !== 404) {
      return { passed: false, error: `상태 코드 ${res.status} 반환됨. (요청 거부 안됨)`, cause: `API 경로(${endpoint})에 로그인(인증) 체크 로직이 없습니다. Next.js 미들웨어나 라우트 핸들러에서 세션/토큰 검증 코드를 추가하세요.`, debug: lastDebug };
    }
    return { passed: true };
  },

  async anonymous_note_write() {
    const res = await fetchApi('POST', config.apiBase);
    if (res.status !== 401 && res.status !== 403) {
      return { passed: false, error: `상태 코드 ${res.status} 반환됨.`, cause: `POST ${config.apiBase} 경로가 로그인하지 않은 사용자에게 열려있습니다. 데이터를 쓰기 전에 인증을 확인하는 로직을 추가하세요.`, debug: lastDebug };
    }
    return { passed: true };
  },

  async repository_secret_scan() {
    try {
      const log = execSync('git log -p', { encoding: 'utf8', maxBuffer: 1024 * 1024 * 10 });
      if (log.includes('SUPABASE_SERVICE_ROLE_KEY') || log.includes('-----BEGIN PRIVATE KEY-----')) {
        return { passed: false, error: "Git 커밋 기록에서 민감한 비밀키(Secret Key)가 발견되었습니다.", cause: "코드 저장소에 절대로 비밀키를 올리면 안 됩니다. BFG 도구 등으로 히스토리를 정리하고 .env로 관리하세요." };
      }
    } catch (e) { /* Git 저장소가 아니거나 커밋이 없는 경우 무시 */ }
    return { passed: true };
  },

  async scan_client_bundles(attackId) {
    try {
      const res = await fetch(config.targetUrl);
      if (!res.ok) throw new Error("대상 URL에 접속할 수 없습니다.");
      const html = await res.text();
      const scripts = [...html.matchAll(/<script[^>]+src="([^"]+)"/g)].map(m => m[1]);
      
      const jwtRegex = /(?:eyJ[A-Za-z0-9-_]+\.){2}[A-Za-z0-9-_]+/;
      
      for (let src of scripts) {
        if (!src.startsWith('http')) src = `${config.targetUrl}${src.startsWith('/') ? '' : '/'}${src}`;
        const sRes = await fetch(src);
        const sBody = await sRes.text();
        
        if (attackId === 'built_bundle_secret_scan') {
          if (sBody.includes('SUPABASE_SERVICE_ROLE_KEY') || jwtRegex.test(sBody)) {
            return { passed: false, error: `클라이언트 번들 파일(${src})에서 JWT 형태의 비밀키 유출 발견`, cause: "서버에서만 사용해야 하는 키가 프론트엔드 자바스크립트에 포함되었습니다. 환경변수 설정 시 접두사(NEXT_PUBLIC_ 등)에 주의하세요.", debug: { req: `GET ${src}`, status: sRes.status, body: sBody } };
          }
        } else if (attackId === 'static_seed_data_scan') {
          if (sBody.toLowerCase().includes('private note')) {
            return { passed: false, error: `클라이언트 번들 파일(${src})에서 하드코딩된 Seed 데이터 발견`, cause: "초기 데이터 배열이 클라이언트 컴포넌트에 하드코딩 또는 임포트되었습니다. 민감한 데이터는 API를 통해 동적으로 통신하세요.", debug: { req: `GET ${src}`, status: sRes.status, body: sBody } };
          }
        }
      }
    } catch (e) {
      return { passed: false, error: e.message, cause: "입력하신 사이트 주소(--url)가 정확한지, 서버가 켜져 있는지 확인해 주세요." };
    }
    return { passed: true };
  },

  async invalid_token_tests(attackId) {
    let token = "";
    if (attackId === 'forged_login_token') token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    
    const res = await fetchApi('GET', config.apiBase, token ? { 'Authorization': `Bearer ${token}` } : {});
    if (res.status !== 401 && res.status !== 403) {
      return { passed: false, error: `상태 코드 ${res.status} 반환됨. (요청 거부 안 됨)`, cause: `올바르지 않은 토큰(위조/만료/오류)인데도 API가 뚫렸습니다. 서버에서 JWT 토큰의 서명(signature), 만료일(exp), 대상(aud)을 정확히 검증하세요.`, debug: lastDebug };
    }
    return { passed: true };
  },

  async bola_tests(attackId) {
    if (!config.userToken) {
      return { passed: false, error: "테스트용 JWT 토큰(--token)이 제공되지 않음", cause: "이 BOLA 취약점 테스트를 진행하려면 실제 로그인한 유저의 토큰이 필요합니다. CLI 인자나 .env 파일(USER_TOKEN)에 토큰을 설정해 주세요." };
    }
    const method = attackId === 'foreign_note_delete' ? 'DELETE' : 'GET';
    const endpoint = `${config.apiBase}/99999`;
    const res = await fetchApi(method, endpoint, { 'Authorization': `Bearer ${config.userToken}` });
    if (res.status === 200 || res.status === 201 || res.status === 204) {
      return { passed: false, error: `다른 사람의 데이터(ID 99999)에 대해 상태 코드 ${res.status} 반환됨 (작업 성공)`, cause: "BOLA(IDOR) 취약점이 발견되었습니다! 토큰의 유저 ID와 조작하려는 데이터의 실제 소유자 ID가 일치하는지 확인하는 검증 로직을 추가하세요.", debug: lastDebug };
    }
    return { passed: true };
  }
};

async function dispatchAttack(attackId) {
  if (['anonymous_note_read', 'anonymous_note_list'].includes(attackId)) return await AttackHandlers.check_anonymous_read(attackId);
  if (attackId === 'anonymous_note_write') return await AttackHandlers.anonymous_note_write();
  if (attackId === 'repository_secret_scan') return await AttackHandlers.repository_secret_scan();
  if (['built_bundle_secret_scan', 'static_seed_data_scan'].includes(attackId)) return await AttackHandlers.scan_client_bundles(attackId);
  if (attackId === 'forged_login_token') return await AttackHandlers.invalid_token_tests(attackId);
  if (attackId === 'r3_judge_owned_note') return await AttackHandlers.bola_tests(attackId);
  
  return { passed: true }; 
}

// ============================================================================
// 6. 메인 테스트 루프 (Main Event Loop)
// ============================================================================
async function main() {
  console.log(`${C.bold}${C.blue}=== 🛡️ 자동 방어 심사 Pre-check CLI ===${C.reset}`);
  console.log(`현재 버전 보안 기준(2026-10-01)으로 점검을 시작합니다.\n`);

  let pass = 0, fail = 0, skip = 0;

  for (const check of SECURITY_CHECKS) {
    if (config.stepFilter && check.step !== config.stepFilter) { skip++; continue; }
    if (config.waveFilter && check.wave !== config.waveFilter) { skip++; continue; }
    
    console.log(`[Step ${check.step} / Wave ${check.wave}] 점검 중: ${check.name}...`);
    
    try {
      const result = await dispatchAttack(check.id);
      if (result.passed) {
        console.log(`  ${C.green}✔ 안전함 (PASS)${C.reset}`);
        pass++;
      } else {
        printDiagnostic(check, result.error, result.cause, result.debug);
        fail++;
      }
    } catch (err) {
      printDiagnostic(check, `에러 발생: ${err.message}`, "스크립트 자체 또는 네트워크 오류입니다. 프론트엔드 서버가 켜져 있는지 확인하세요.");
      fail++;
    }
  }

  console.log(`\n${C.bold}=== 점검 요약 (Summary) ===${C.reset}`);
  console.log(`${C.green}통과(Passed): ${pass}${C.reset}, ${C.red}실패(Failed): ${fail}${C.reset}, ${C.yellow}건너뜀(Skipped): ${skip}${C.reset}`);
  
  if (fail > 0) {
    console.log(`\n${C.red}⚠️ 취약점이 발견되었습니다. 위의 해결 가이드를 참고하여 서버 코드를 수정해 주세요.${C.reset}`);
    process.exit(1);
  } else {
    console.log(`\n${C.green}✅ 모든 보안 점검을 통과했습니다! 심사 엔진에 제출할 준비가 되었습니다.${C.reset}`);
  }
}

// 실행
main();
