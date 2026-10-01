import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { testRegistry, setupHooks } from './test_runner/core/runner.mjs';
import { SecurityAssertError } from './test_runner/core/client.mjs';

// Load .env file automatically if it exists (No external dotenv dependency needed)
if (fs.existsSync('.env')) {
  const envData = fs.readFileSync('.env', 'utf8');
  for (const line of envData.split('\n')) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const [key, ...rest] = trimmed.split('=');
      if (key && rest.length && !process.env[key.trim()]) {
        process.env[key.trim()] = rest.join('=').trim().replace(/^['"]|['"]$/g, '');
      }
    }
  }
}

const options = {
  url: { type: 'string' },
  tokenA: { type: 'string' },
  tokenB: { type: 'string' },
  adminToken: { type: 'string' }
};
const { values } = parseArgs({ options, strict: false });
if (values.url) process.env.TARGET_URL = values.url;
if (values.tokenA) process.env.TOKEN_A = values.tokenA;
if (values.tokenB) process.env.TOKEN_B = values.tokenB;
if (values.adminToken) process.env.ADMIN_TOKEN = values.adminToken;

const COLORS = {
  reset: "\x1b[0m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  magenta: "\x1b[35m",
  bold: "\x1b[1m"
};

function loadLatestRoster() {
  const rulesDir = path.join(process.cwd(), 'rules');
  if (!fs.existsSync(rulesDir)) return {};
  const files = fs.readdirSync(rulesDir)
    .filter(f => f.startsWith('roster_') && f.endsWith('.json'))
    .sort((a, b) => fs.statSync(path.join(rulesDir, b)).mtimeMs - fs.statSync(path.join(rulesDir, a)).mtimeMs);
  
  if (files.length === 0) return {};
  try {
    return JSON.parse(fs.readFileSync(path.join(rulesDir, files[0]), 'utf8'));
  } catch (e) {
    return {};
  }
}
const roster = loadLatestRoster();

async function loadScenarios() {
  await import('./test_runner/scenarios/core_security_tests.mjs');
  await import('./test_runner/scenarios/advanced_tests.mjs');
  await import('./test_runner/scenarios/wave2_auth_static.mjs');
  await import('./test_runner/scenarios/wave3_device_anomaly.mjs');
  await import('./test_runner/scenarios/wave4_complex_attacks.mjs');
}

async function runAll() {
  console.log(`\n${COLORS.bold}${COLORS.cyan}============================================================${COLORS.reset}`);
  console.log(`${COLORS.bold}${COLORS.cyan} 🛡️ True Stateful QA / Security Integration Test Framework ${COLORS.reset}`);
  console.log(`${COLORS.bold}${COLORS.cyan}============================================================${COLORS.reset}\n`);

  await loadScenarios();
  
  for (const hook of setupHooks) {
    try {
      await hook();
    } catch (e) {
      console.log(`${COLORS.red}❌ 인프라 셋업 실패: ${e.message}${COLORS.reset}`);
    }
  }

  let passed = 0;
  let failed = 0;
  let warned = 0;
  const failedIds = [];
  const warnedIds = [];

  for (const t of testRegistry) {
    const displayName = roster[t.attackId] ? `${roster[t.attackId]} (${t.attackId})` : t.attackId;
    try {
      await t.fn();
      console.log(`[${COLORS.green}✅ PASS${COLORS.reset}] ${t.wave} - ${COLORS.magenta}${displayName}${COLORS.reset}: ${t.description}`);
      passed++;
    } catch (err) {
      const isWarn = err instanceof SecurityAssertError && err.type === 'WARN';
      
      if (isWarn) {
        console.log(`[${COLORS.yellow}⚠️ WARN${COLORS.reset}] ${t.wave} - ${COLORS.magenta}${displayName}${COLORS.reset}: ${t.description}`);
        console.log(`   ↳ ${COLORS.yellow}💡 이유: ${err.message}${COLORS.reset}`);
        warned++;
        warnedIds.push(t.attackId);
      } else {
        console.log(`[${COLORS.red}❌ FAIL${COLORS.reset}] ${t.wave} - ${COLORS.magenta}${displayName}${COLORS.reset}: ${t.description}`);
        console.log(`   ↳ ${COLORS.red}💡 이유: ${err.message}${COLORS.reset}`);
        failed++;
        failedIds.push(t.attackId);
      }
    }
  }

  // Dashboard 출력
  console.log(`\n${COLORS.bold}====================== [ TEST SUMMARY ] ======================${COLORS.reset}`);
  console.log(`Total Scenarios: ${testRegistry.length}`);
  console.log(`${COLORS.green}✅ Passed: ${passed}${COLORS.reset}`);
  console.log(`${COLORS.red}❌ Failed (Security Vulnerable): ${failed}${COLORS.reset}`);
  console.log(`${COLORS.yellow}⚠️ Warn (Untestable/Missing): ${warned}${COLORS.reset}`);
  
  if (failed > 0) {
    console.log(`\n${COLORS.bold}${COLORS.red}🚨 보안 취약점 (Fix Required):${COLORS.reset}`);
    console.log(`${COLORS.red}${failedIds.join(', ')}${COLORS.reset}`);
  }
  
  if (warned > 0) {
    console.log(`\n${COLORS.bold}${COLORS.yellow}🚧 미구현/테스트 불가 (Pending Implementation):${COLORS.reset}`);
    console.log(`${COLORS.yellow}${warnedIds.join(', ')}${COLORS.reset}`);
  }
  
  if (failed === 0 && warned === 0) {
    console.log(`\n${COLORS.green}🎉 모든 엣지 케이스 보안 검증을 통과했습니다!${COLORS.reset}`);
  }
  
  process.exit(failed > 0 ? 1 : 0);
}

runAll().catch(console.error);
