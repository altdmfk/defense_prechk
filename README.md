# 🛡️ True Stateful QA / Security Integration Test Framework

이 프로젝트는 백엔드 서버의 보안 취약점과 인가(Authorization) 로직을 검증하기 위한 **다단계 상태 전이(True Stateful) 기반 통합 보안 테스트 프레임워크**입니다. 단순한 단일 엔드포인트 찌르기를 넘어, 실제 데이터를 생성하고 다중 사용자 컨텍스트를 오가며 정밀한 보안 엣지 케이스를 검증합니다.

## ✨ 주요 특징

*   **다중 신원 컨텍스트 (Multi-Identity Context)**: `User A`, `User B`, `Admin` 등 여러 역할의 토큰을 동적으로 발급받아 타인 리소스 접근(BOLA/IDOR), 권한 상승(Privilege Escalation) 등을 완벽히 재현합니다.
*   **True Stateful 검증**: 리소스 생성 ➔ 공격 시도 ➔ 결과 확인 ➔ **무결성(Immutability) 교차 검증**의 완전한 라이프사이클을 수행합니다.
*   **3-Tier Reporting Dashboard**:
    *   `[✅ PASS]`: 공격이 서버 미들웨어에 의해 올바르게 차단됨 (보안 성공).
    *   `[❌ FAIL]`: 공격이 성공해버려 데이터가 오염되거나 통과됨 (**보안 취약점 발견**).
    *   `[⚠️ WARN]`: 해당 API가 아직 구현되지 않았거나(404), 테스트 사전 조건(로그인 실패 등)이 맞지 않아 테스트가 보류됨 (미구현).

## 🚀 실행 방법

### 1. 테스트용 더미 서버 실행 (포트 4000)
프레임워크가 타격할 타겟 서버가 로컬에 실행되어 있어야 합니다. 이 프로젝트에 포함된 고의로 취약하게 만들어진 샌드백 서버(`dummy_server.js`)를 4000번 포트에 띄우려면 먼저 다음 명령을 실행하세요:

```bash
# 다른 터미널 창을 열고 실행
node dummy_server.js
```

### 2. 테스트 스위트 실행
기본적으로 환경 변수 `TARGET_URL`을 바라보며, 옵션이 없을 시 `http://localhost:4000`을 타격합니다.

```bash
# 기본 실행 (로컬 4000번 포트 공격)
node precheck.mjs

# 특정 프로덕션/스테이징 URL 공격
node precheck.mjs --url="https://api.your-domain.com"
```

## 🛠️ 백엔드 필수 구현 API (사전 조건)

프레임워크가 정상적으로 41개의 시나리오를 구동하기 위해, 타겟 서버는 최소한 아래의 인증 API를 구현하고 있어야 합니다. (이 API들이 없다면 모든 테스트가 `[⚠️ WARN]`으로 처리됩니다.)

1.  `POST /api/auth/register`: `{ email, password, role }`을 받아 가입 처리 (201 반환)
2.  `POST /api/auth/login`: `{ email, password }`를 받아 `{ token, user_id }` 반환

*※ 만약 인증 API 주소나 JSON 응답 스펙이 다르다면, `test_runner/fixtures/auth_context.mjs` 파일을 서버 환경에 맞게 수정하여 사용하세요.*

## 📂 디렉토리 구조

*   `precheck.mjs`: 테스트 프레임워크 메인 엔트리포인트 및 대시보드 리포터
*   `test_runner/core/`: API 클라이언트, 커스텀 러너, 공유 컨텍스트 등 코어 모듈
*   `test_runner/fixtures/`: 테스트 픽스처 (다중 유저 인증 컨텍스트, 리소스 시드 생성기)
*   `test_runner/scenarios/`: 41개의 엣지 케이스 시나리오 (Wave 2 ~ Wave 4)
*   `dummy_server.js`: 프레임워크를 테스트하기 위해 고의로 취약하게 만들어진 샌드백 서버
*   `rules/roster_*.json`: 공격 ID와 시나리오 설명을 매핑하는 룰 파일

## 📝 41개 보안 검증 항목 (Wave 2 ~ 4)

1.  **Wave 2 (Auth & Static)**: JWT 변조(서명 위조, 만료, Aud 불일치), 정적 파일 내 시크릿 노출 스캔, 무인증 접근 방어, DB/Origin 직접 우회 타격 방어.
2.  **Wave 3 (Device & Anomaly)**: 미등록 기기 차단, 비정상 지역(GeoIP) 접근 통제, 동시 다발적 락(Race Condition) 검증, 타 테넌트(Cross-Zone) 격리 방어.
3.  **Wave 4 (Complex Attacks)**: 무서명 복구 공격, 기기 불일치+폐기 토큰 복합 타격 등 중첩된 미들웨어 로직의 안전성 검증.
