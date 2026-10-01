# Defense Pre-check CLI Tool

배포된 웹 서비스와 GitHub 저장소를 방어 심사 엔진에 제출하기 전에 사전 검증하는 Node.js CLI 도구입니다. 외부 라이브러리 설치 없이 Node.js 내장 모듈만으로 동작합니다.

## 점검 항목

| Step | Wave | 항목 |
|------|------|------|
| 1 | 1 | API 인증 우회 (GET 조회) |
| 1 | 2 | API 인증 우회 (POST 쓰기) |
| 2 | 1 | Git 히스토리 내 비밀키 유출 |
| 2 | 2 | 클라이언트 번들(JS) JWT 유출 |
| 2 | 3 | 클라이언트 번들(JS) Seed 데이터 하드코딩 |
| 3 | 1 | 위조된 JWT 토큰 서명(Signature) 검증 |
| 4 | 1 | 타인 데이터 불법 접근 (BOLA/IDOR) |

## 시작하기

### 1. 환경 변수(.env) 설정 (선택 사항)

프로젝트 루트에 `.env` 파일을 생성하면 매번 옵션을 입력하지 않아도 됩니다. `.env.example`을 참고하세요.

```env
TARGET_URL=https://your-deployed-site.com
USER_TOKEN=eyJhbGciOi...
API_BASE=/api/notes
```

### 2. 실행

`.env`에 `TARGET_URL`이 설정되어 있으면 `--url` 없이 바로 실행할 수 있습니다.

```bash
node precheck.mjs
```

```bash
# URL 직접 지정
node precheck.mjs --url https://your-deployed-site.com

# 인증 토큰 및 API 경로 지정
node precheck.mjs --url https://your-deployed-site.com --token "eyJhbGciOiJIUzI..." --api-base "/api/v1/notes"

# Step 또는 Wave 필터링
node precheck.mjs --step 2
node precheck.mjs --step 2 --wave 1
```

## 실패 시 출력 정보

- 어떤 보안 취약점이 발견되었는지
- 서버의 실제 응답 (상태 코드, 응답 본문)
- 코드 어느 부분을 수정해야 하는지에 대한 가이드
