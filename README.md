# Defense Pre-check CLI Tool

방어 심사 엔진 제출 전, 웹 서비스와 저장소의 보안 상태를 사전 검증하는 독립 실행형 Node.js CLI 도구입니다. 41개 핵심 보안/컴플라이언스 항목(인증, 세션 무효화, RBAC, IDOR/BOLA, 번들 스캔 등)을 외부 라이브러리 없이 진단합니다.

## 주요 기능

- **독립 실행 (Standalone)**: 단일 스크립트(`precheck.mjs`)로 41개 테스트 자동 실행
- **복합 시나리오 (Multi-Step)**: 세션 무효화 후 재접근, RBAC 권한 분리, IDOR 교차 테넌트 접근 등 실제 공격 시나리오 모사
- **진단 리포트 (Diagnostic)**: 취약점 적발 시 기대 결과, 실제 응답, 해결 가이드(Remediation)를 포함한 상세 리포트 제공

## 요구 사항
- Node.js 18 이상

## 실행 방법

`.env` 파일에 환경 변수(`TARGET_URL`, `USER_TOKEN`, `ADMIN_TOKEN`)를 설정하거나, CLI 인자로 직접 전달하여 실행할 수 있습니다.

```bash
# 기본 실행 (.env 설정 기준 또는 기본값 http://localhost:4000)
node precheck.mjs

# URL 및 토큰 직접 지정
node precheck.mjs --url "https://api.staging.internal" --token "JWT_STUDENT" --admin-token "JWT_INSTRUCTOR"

# 특정 단계(Step)의 테스트만 실행
node precheck.mjs --step 9
```

## 취약점 모사 테스트 (Dummy Server)

진단 스크립트가 취약점을 어떻게 적발해 내는지 확인하려면, 함께 제공되는 취약한 더미 서버(`dummy_server.js`)를 활용하여 테스트할 수 있습니다. 더미 서버는 모든 방어 로직이 고의적으로 누락되어 있습니다.

1. **더미 서버 실행**: 별도의 터미널 창에서 서버를 구동합니다.
   ```bash
   node dummy_server.js
   ```
2. **테스트 런너 실행**: 다른 터미널 창에서 `--url` 인자 없이 런너를 실행하면 더미 서버(`http://localhost:4000`)를 타겟으로 40여 개의 취약점이 모두 정상 적발(FAIL)되는 것을 확인할 수 있습니다. (Git 커밋 히스토리 검증 로직 제외)
   ```bash
   node precheck.mjs
   ```

## 리포트 예시

취약점이 적발될 경우 출력되는 진단 카드(Diagnostic Card) 예시입니다.

```text
  ❌ FAIL: Anonymous access allowed

      --- DIAGNOSTIC CARD ---
      * Test Case ID: anonymous_note_read
      * Expected Server Invariant: 401 Unauthorized or 403 Forbidden
      * Actual Server Output: {"status":200,"body":"..."}
      * Remediation Advice: Implement authentication middleware to block unauthenticated requests.
      -----------------------
```
